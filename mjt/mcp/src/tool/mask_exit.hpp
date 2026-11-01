#pragma once

#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "libca/core/datatype.hpp"
#include "libca/core/status.hpp"

#include "mjbase/project/analysis_db.hpp"
#include "mjbase/project/mask_evaluator.hpp"

#include "project_session.hpp"

namespace mjt::mcp {

///@brief 一次出口批量掩蔽的侧车汇总（响应 `mask` 字段，#121 §4.5）。
struct MaskExitSummary final
{
    bool        active = false;        ///< 会话装载了 mask 出口（bundle 有 analysis.mjdb）
    std::string trustLevel;            ///< "trusted" / "untrusted"
    ca::usize   rules = 0;             ///< 装载的规则条数
    ca::usize   evaluated = 0;         ///< 求值的文本条数
    ca::usize   masked = 0;            ///< 遮蔽条数（占位符出口）
    ca::usize   allowedByRule = 0;     ///< allow 规则放行条数（选择性放行的审计计数）
    ca::usize   overrideBlocked = 0;   ///< allow 命中被 suspect 压下的条数（留痕计数）
    ca::usize   suspect = 0;           ///< 带 suspect 旗标的条数
    ca::usize   lengthGated = 0;       ///< 超长度门（default_action 兜底）的条数
    bool        hitPersistenceFailed = false; ///< 命中记账落库失败（尽力而为面）
};

///@brief 会话级 mask 出口状态：惰性打开工程 bundle 的 `analysis.mjdb`，
///装载规则集与信任级别，为文本出口（search kind=strings）提供统一求值。
///
///- 装载点：首个掩蔽出口调用，会话内一次（规则编辑中途不热更，重开会话
///  生效）；bundle 无 `analysis.mjdb` → 直通（inactive），老 bundle 零行为
///  漂移；库存在但打不开/版本不符/规则装载失败 → 出口 fail-loud（与
///  schema 版本门纪律一致，掩蔽面不静默降级——不可信库的遮蔽失效是安全
///  事件，不是警告）。
///- 求值核心在 mjbase（MaskEvaluator，纯函数面）；本类只做装载、出口
///  渲染（占位符替换）与命中记账（recordMaskRuleHits，尽力而为：出口是
///  读路径，记账失败以汇总字段呈现，不使查询失败）。
///- 线程模型：全部调用在工具执行锁（executionMutex_）内；AnalysisDb 连接
///  为会话私有（非线程安全）。
class MaskExitState final
{
public:
    MaskExitState() = default;
    ~MaskExitState();
    MaskExitState(MaskExitState&&) noexcept;
    MaskExitState& operator=(MaskExitState&&) noexcept;
    MaskExitState(const MaskExitState&)            = delete;
    MaskExitState& operator=(const MaskExitState&) = delete;

    ///@brief 惰性装载（幂等）。@param projectDir 工程 bundle 目录。
    ///       无库静默 inactive；有库失败返回错误（fail-loud）。
    ca::Status ensureLoaded(const std::string& projectDir);

    bool active() const noexcept;

    ///@brief 就地掩蔽一批出口文本（指针一一对应调用方行），产出汇总并
    ///       记账。inactive 直通（summary.active=false）。
    ca::Status apply(std::vector<std::string*>& values, MaskExitSummary& out);

private:
    bool loadAttempted_          = false;
    bool active_                 = false;
    std::string projectDir_;
    std::unique_ptr<mjbase::project::AnalysisDb>            db_;         ///< ReadWrite，命中记账
    std::shared_ptr<const mjbase::project::MaskEvaluator>   evaluator_;  ///< 不可变判定面
};

///@brief 出口接线入口：惰性分配会话 mask 状态、装载并就地掩蔽 values。
///       返回错误 = 掩蔽面 fail-loud（调用方转工具错误）。
ca::Status applyMaskExit(ProjectSession&        session,
                         std::vector<std::string*>& values,
                         MaskExitSummary&       out);

///@brief 汇总 → 响应侧车 JSON（`mask` 字段；仅 active 时调用）。
nlohmann::json maskSummaryJson(const MaskExitSummary& summary);

}   //namespace mjt::mcp
