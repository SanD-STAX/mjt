/// @file        analysis_ingest.hpp
/// @brief       工作区 → 分析数据库的整库导入桥。
///
/// 职责边界：workspace 负责从 class 字节解码（ClassInfo + ReferenceScan），
/// mjbase::project::AnalysisDb 负责持久化与查询。本桥把两者接起来：
/// - 主容器全部 class 的头事实与成员清单写入 `ingestClasses`；
/// - 主容器 class 发出的直接引用（方法/字段/类型）写入 `replaceReferences`；
/// - supporting JAR 只作为引用目标出现，其自身 class 不登记、其发出的引用
///   不写入（支持库可能包含整个 JDK，不属于工程身份面）。
///
/// 两次写入各自单事务；第二步失败时类事实已提交、引用仍是旧集合。整库重建
/// 可安全重跑：类身份 upsert 不改 ID，引用是整体替换。
#pragma once

#include <string>
#include <vector>

#include "libca/core/datatype.hpp"
#include "libca/core/result.hpp"
#include "libca/str/utf8_string.hpp"

#include "mjbase/project/analysis_db.hpp"
#include "workspace_types.hpp"

namespace mjt::workspace {

class WorkspaceBase;

/// @brief 导入失败来源。
enum class AnalysisIngestErrorKind : ca::u8
{
    Workspace, ///< 工作区读取/扫描失败
    Database,  ///< 分析数据库写入失败
};

/// @brief 导入诊断（message 为 std::string：Result 错误通道要求可拷贝）。
struct AnalysisIngestError
{
    AnalysisIngestErrorKind kind = AnalysisIngestErrorKind::Database;
    std::string             message;
};

/// @brief 一次整库导入的规模统计。
struct AnalysisIngestStats
{
    ca::usize classes    = 0;
    ca::usize members    = 0;
    ca::usize references = 0;
};

/// @brief 把工作区主容器的类/成员/直接引用整库写入分析数据库。
///
/// 要求 @p db 已以读写方式打开；本函数不创建/关闭数据库。
ca::Result<AnalysisIngestStats, AnalysisIngestError> ingestIntoAnalysisDb(
    const WorkspaceBase& workspace, mjbase::project::AnalysisDb& db);

}   // namespace mjt::workspace
