#include "mask_exit.hpp"

#include <filesystem>
#include <utility>

#include "mjbase/project/mask_types.hpp"

namespace mjt::mcp {
namespace {

///@brief AnalysisDbErrorKind → ca::StatusCode（掩蔽面 fail-loud 的呈现码）。
ca::StatusCode statusCodeOf(mjbase::project::AnalysisDbErrorKind kind)
{
    using K = mjbase::project::AnalysisDbErrorKind;
    switch (kind) {
    case K::Invalid: return ca::StatusCode::INVALID_ARGUMENT;
    case K::Schema: return ca::StatusCode::FAILED_PRECONDITION;
    case K::ReadOnly: return ca::StatusCode::PERMISSION_DENIED;
    case K::Io: return ca::StatusCode::UNAVAILABLE;
    case K::Open:
    case K::Sqlite: break;
    }
    return ca::StatusCode::INTERNAL;
}

ca::Status maskDbStatus(mjbase::project::AnalysisDbError error, const char* operation)
{
    return ca::ErrStatus(statusCodeOf(error.kind),
                         std::string(operation) + ": " + error.message.to_std_string());
}

}   //namespace

MaskExitState::~MaskExitState() = default;

MaskExitState::MaskExitState(MaskExitState&&) noexcept = default;

MaskExitState& MaskExitState::operator=(MaskExitState&&) noexcept = default;

ca::Status MaskExitState::ensureLoaded(const std::string& projectDir)
{
    if (loadAttempted_) return ca::OkStatus();
    loadAttempted_ = true;
    projectDir_    = projectDir;

    // bundle 内分析库固定文件名走单源（project_session.hpp 的
    // kAnalysisDbFileName），不再本地持一份同值常数。
    const auto dbPath = std::filesystem::path(projectDir) / kAnalysisDbFileName;
    std::error_code  ec;
    if (!std::filesystem::is_regular_file(dbPath, ec)) {
        return ca::OkStatus();   ///< 老bundle/未建库：直通（inactive）
    }

    auto opened = mjbase::project::AnalysisDb::open(
        ca::str::Utf8StringRef::from_string_view(dbPath.string()),
        mjbase::project::AnalysisDbOpenMode::ReadWrite);
    if (opened.is_err()) {
        return maskDbStatus(std::move(opened).unwrap_err(), "open mask exit analysis db");
    }
    db_ = std::make_unique<mjbase::project::AnalysisDb>(std::move(opened).unwrap());

    auto rules = db_->listMaskRules();
    if (rules.is_err()) {
        return maskDbStatus(std::move(rules).unwrap_err(), "load mask rules");
    }
    auto trust = db_->maskTrustLevel();
    if (trust.is_err()) {
        return maskDbStatus(std::move(trust).unwrap_err(), "load mask trust level");
    }

    //数据面行 → 求值器构建输入投影：(priority, rule_id) 序即匹配序。
    std::vector<mjbase::project::DbMaskRule> ruleRows = std::move(rules).unwrap();
    std::vector<mjbase::project::MaskRuleSpec> specs;
    specs.reserve(ruleRows.size());
    for (const mjbase::project::DbMaskRule& row : ruleRows) {
        mjbase::project::MaskRuleSpec spec;
        spec.ruleId   = row.ruleId;
        spec.priority = row.priority;
        spec.pattern  = std::string_view(reinterpret_cast<const char*>(row.pattern.data()),
                                        row.pattern.byte_length());
        spec.action   = row.action;
        specs.push_back(spec);
    }
    auto built = mjbase::project::MaskEvaluator::build(specs, trust.unwrap());
    if (built.is_err()) {
        return ca::ErrStatus(ca::StatusCode::INTERNAL,
                             "build mask evaluator: " + std::move(built).unwrap_err().message.to_std_string());
    }
    evaluator_ =
        std::make_shared<const mjbase::project::MaskEvaluator>(std::move(built).unwrap());
    active_ = true;
    return ca::OkStatus();
}

bool MaskExitState::active() const noexcept
{
    return active_;
}

ca::Status MaskExitState::apply(std::vector<std::string*>& values, MaskExitSummary& out)
{
    out = MaskExitSummary{};
    if (!active_ || evaluator_ == nullptr) return ca::OkStatus();

    out.active     = true;
    out.trustLevel = evaluator_->trust() == mjbase::project::MaskTrustLevel::Untrusted
                         ? "untrusted"
                         : "trusted";
    out.rules = evaluator_->ruleCount();

    //命中归因收集（含被 suspect 压制的 allow 命中：复盘要看见 allow 试图
    //放行可疑内容的信号），出口批结束后单事务记账。
    std::vector<ca::i64> matchedRules;
    for (std::string* value : values) {
        const auto decision = evaluator_->evaluate(*value);
        ++out.evaluated;
        if (decision.suspect) ++out.suspect;
        if (decision.via == mjbase::project::MaskDecisionVia::LengthGate) ++out.lengthGated;
        if (decision.suspectOverrideBlocked) ++out.overrideBlocked;
        if (decision.action == mjbase::project::MaskAction::Mask) {
            ++out.masked;
            //占位符归因只认规则生效的遮蔽；被压 allow 不是遮蔽来源。
            *value = mjbase::project::maskedPlaceholderText(decision).to_std_string();
        }
        else if (decision.via == mjbase::project::MaskDecisionVia::RuleMatch) {
            ++out.allowedByRule;
        }
        if (decision.ruleId > 0) matchedRules.push_back(decision.ruleId);
    }

    if (!matchedRules.empty() && db_ != nullptr) {
        if (db_->recordMaskRuleHits(matchedRules).is_err()) out.hitPersistenceFailed = true;
    }
    return ca::OkStatus();
}

ca::Status applyMaskExit(ProjectSession&            session,
                         std::vector<std::string*>& values,
                         MaskExitSummary&           out)
{
    out = MaskExitSummary{};
    if (values.empty()) return ca::OkStatus();
    //惰性分配：掩蔽出口是可选项，未触达的会话零成本。调用点在工具执行锁
    //内，分配与装载串行。
    if (!session.maskExit) session.maskExit = std::make_unique<MaskExitState>();
    MaskExitState& state = *session.maskExit;
    if (auto status = state.ensureLoaded(session.projectDir); status.is_err()) return status;
    return state.apply(values, out);
}

nlohmann::json maskSummaryJson(const MaskExitSummary& summary)
{
    nlohmann::json payload = {{"active", summary.active},
                              {"trust_level", summary.trustLevel},
                              {"rules", summary.rules},
                              {"evaluated", summary.evaluated},
                              {"masked", summary.masked},
                              {"allowed_by_rule", summary.allowedByRule},
                              {"override_blocked", summary.overrideBlocked},
                              {"suspect", summary.suspect},
                              {"length_gated", summary.lengthGated}};
    if (summary.hitPersistenceFailed) payload["hit_persistence"] = "failed";
    return payload;
}

}   //namespace mjt::mcp
