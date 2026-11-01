#include "analysis_ingest.hpp"

#include <string>
#include <unordered_set>
#include <utility>

#include "reference_scan.hpp"
#include "workspace.hpp"

namespace mjt::workspace {
namespace {

using ca::str::Utf8String;

Utf8String utf8(const std::string& value)
{
    return Utf8String::from_data_unchecked(reinterpret_cast<const ca::u8*>(value.data()),
                                           value.size());
}

AnalysisIngestError workspaceError(const WorkspaceErrorInfo& error)
{
    AnalysisIngestError output;
    output.kind    = AnalysisIngestErrorKind::Workspace;
    output.message = error.message;
    return output;
}

AnalysisIngestError databaseError(mjbase::project::AnalysisDbError error)
{
    AnalysisIngestError output;
    output.kind    = AnalysisIngestErrorKind::Database;
    output.message = error.message.to_std_string();
    return output;
}

}   // namespace

ca::Result<AnalysisIngestStats, AnalysisIngestError> ingestIntoAnalysisDb(
    const WorkspaceBase& workspace, mjbase::project::AnalysisDb& db)
{
    auto classInfos = workspace.listClasses();
    if (classInfos.is_err()) {
        return ca::core::Err(workspaceError(std::move(classInfos).unwrap_err()));
    }

    std::unordered_set<std::string> primaryClasses;
    std::vector<mjbase::project::DbClassInput> classes;
    const auto classList = std::move(classInfos).unwrap();
    classes.reserve(classList.size());
    for (const ClassInfo& info : classList) {
        mjbase::project::DbClassInput input;
        input.internalName = utf8(info.internalName);
        input.superName    = utf8(info.superName);
        input.access       = info.access;
        input.version      = info.version;
        input.interfaces.reserve(info.interfaces.size());
        for (const std::string& interfaceName : info.interfaces) {
            input.interfaces.push_back(utf8(interfaceName));
        }
        input.members.reserve(info.fields.size() + info.methods.size());
        for (const FieldInfo& field : info.fields) {
            mjbase::project::DbMemberInput member;
            member.kind       = mjbase::project::DbMemberKind::Field;
            member.name       = utf8(field.name);
            member.descriptor = utf8(field.descriptor);
            member.access     = field.access;
            input.members.push_back(std::move(member));
        }
        for (const MethodInfo& method : info.methods) {
            mjbase::project::DbMemberInput member;
            member.kind       = mjbase::project::DbMemberKind::Method;
            member.name       = utf8(method.name);
            member.descriptor = utf8(method.descriptor);
            member.access     = method.access;
            input.members.push_back(std::move(member));
        }
        primaryClasses.insert(info.internalName);
        classes.push_back(std::move(input));
    }

    AnalysisIngestStats stats;
    stats.classes = classes.size();
    for (const mjbase::project::DbClassInput& input : classes) stats.members += input.members.size();

    auto ingested = db.ingestClasses(std::move(classes));
    if (ingested.is_err()) {
        return ca::core::Err(databaseError(std::move(ingested).unwrap_err()));
    }

    auto scan = workspace.referenceScan();
    if (scan.is_err()) {
        return ca::core::Err(workspaceError(std::move(scan).unwrap_err()));
    }
    const auto references = std::move(scan).unwrap();

    std::vector<mjbase::project::DbReferenceRecord> records;
    records.reserve(references.methodReferences().size() + references.fieldReferences().size() +
                    references.typeReferences().size());

    for (const MethodReference& reference : references.methodReferences()) {
        if (primaryClasses.find(reference.site.sourceClass) == primaryClasses.end()) continue;
        mjbase::project::DbReferenceRecord record;
        record.sourceClass      = utf8(reference.site.sourceClass);
        record.sourceMethod     = utf8(reference.site.sourceMethod);
        record.sourceDescriptor = utf8(reference.site.sourceDescriptor);
        record.insnIndex        = reference.site.insnIndex;
        record.kind             = mjbase::project::DbReferenceKind::Method;
        record.targetClass      = utf8(reference.target.owner);
        record.targetName       = utf8(reference.target.name);
        record.targetDescriptor = utf8(reference.target.descriptor);
        records.push_back(std::move(record));
    }
    for (const FieldReference& reference : references.fieldReferences()) {
        if (primaryClasses.find(reference.site.sourceClass) == primaryClasses.end()) continue;
        mjbase::project::DbReferenceRecord record;
        record.sourceClass      = utf8(reference.site.sourceClass);
        record.sourceMethod     = utf8(reference.site.sourceMethod);
        record.sourceDescriptor = utf8(reference.site.sourceDescriptor);
        record.insnIndex        = reference.site.insnIndex;
        record.kind             = mjbase::project::DbReferenceKind::Field;
        record.targetClass      = utf8(reference.target.owner);
        record.targetName       = utf8(reference.target.name);
        record.targetDescriptor = utf8(reference.target.descriptor);
        records.push_back(std::move(record));
    }
    for (const TypeReference& reference : references.typeReferences()) {
        if (primaryClasses.find(reference.site.sourceClass) == primaryClasses.end()) continue;
        mjbase::project::DbReferenceRecord record;
        record.sourceClass      = utf8(reference.site.sourceClass);
        record.sourceMethod     = utf8(reference.site.sourceMethod);
        record.sourceDescriptor = utf8(reference.site.sourceDescriptor);
        record.insnIndex        = reference.site.insnIndex;
        record.kind             = mjbase::project::DbReferenceKind::Type;
        record.targetClass      = utf8(reference.targetType);
        records.push_back(std::move(record));
    }

    stats.references = records.size();
    auto replaced    = db.replaceReferences(std::move(records));
    if (replaced.is_err()) {
        return ca::core::Err(databaseError(std::move(replaced).unwrap_err()));
    }
    return ca::core::Ok(stats);
}

}   // namespace mjt::workspace
