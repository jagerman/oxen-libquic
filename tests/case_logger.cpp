// This file contains a Catch2 listener than add oxen logging statements tracing the entry of cases
// and sections in the test suite.
//
// It runs in its own log level; to activate it, run alltests with `-T`/`--test-tracing`.
//
#include "unit_test.hpp"

namespace fmt
{
    template <>
    struct formatter<Catch::StringRef, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const Catch::StringRef& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format({val.data(), val.size()}, ctx);
        }
    };
}  // namespace fmt

namespace oxen::quic::test
{
    using namespace Catch;

    static auto cat = log::Cat("testcase");

    static std::string_view sv(const Catch::StringRef& s)
    {
        return {s.data(), s.size()};
    }

    // Bypass the usual log::trace(...) because we want to fake the source location, and want this
    // even in non-debug builds.
    template <typename... T>
    static void test_trace(const Catch::SourceLineInfo& sli, fmt::format_string<T...> fmt, T&&... args)
    {

        std::string_view filename{sli.file};
        for (const auto& prefix : oxen::log::detail::source_prefixes)
        {
            if (filename.starts_with(prefix))
            {
                filename.remove_prefix(prefix.size());
                if (!filename.empty() && filename[0] == '/')
                    filename.remove_prefix(1);
            }
        }
        while (filename.starts_with("../"))
            filename.remove_prefix(3);

        spdlog::source_loc sloc{filename.data(), static_cast<int>(sli.line), /*function name=*/""};

        cat->log(sloc, log::Level::trace, fmt, std::forward<T>(args)...);
    }

    class CaseLogger : public Catch::EventListenerBase
    {
      public:
        using Catch::EventListenerBase::EventListenerBase;

        static std::string getDescription()
        {
            return "Report test cases and section starting/ending events via oxen-logging";
        }

        void testCaseStarting(const TestCaseInfo& info) override
        {
            test_trace(info.lineInfo, "Starting test case {} ({})", info.name, info.tagsAsString());
        }
        void testCaseEnded(const TestCaseStats& stats) override
        {
            auto& info = *stats.testInfo;
            test_trace(info.lineInfo, "Finished test case {} ({})", info.name, info.tagsAsString());
        }

        void testCasePartialStarting(const Catch::TestCaseInfo& info, uint64_t partNumber) override
        {
            if (partNumber > 0)
                test_trace(info.lineInfo, "↪ Starting test case {} pass {}", info.name, partNumber);
        }

        void testCasePartialEnded(const Catch::TestCaseStats& stats, uint64_t partNumber) override
        {
            auto& info = *stats.testInfo;
            if (partNumber > 0)
                test_trace(info.lineInfo, "↩ Finished test case {} pass {}", info.name, partNumber);
        }

        bool first_sect = true;
        void sectionStarting(const SectionInfo& info) override
        {
            if (first_sect)
                first_sect = false;
            test_trace(info.lineInfo, "  ↪ Entering section {}", info.name);
        }
        void sectionEnded(const SectionStats& stats) override
        {
            auto& info = stats.sectionInfo;
            test_trace(info.lineInfo, "  ↩ Finished section {} in {:.3f}ms", info.name, stats.durationInSeconds * 1000);
        }
    };

}  // namespace oxen::quic::test

CATCH_REGISTER_LISTENER(oxen::quic::test::CaseLogger)
