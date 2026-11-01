//LVT 显示名策略 MCP 出口 E2E（B3，#121 §4.4）。
//
//覆盖：method_get 的 locals 呈现名经 mjbase::analysis 策略判定——jar 名字
//可信时合法名原样透出（deobf 证据）；形态分布整体像垃圾（非法占比 ≥ 1/2）
//时全 jar 归 var<槽位号>。字节码原文不动（class_query kind=bytes 可见原始
//名字字节）。夹具全自造字节（writeFixture jasm 装配 + 结构化编辑写入 LVT），
//零反编译样本入仓。
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "mcp_test_support.hpp"

namespace mjt::mcp {
namespace {

using namespace test_support;

///writeFixture 落盘固定路径，本组测试会经结构化编辑改写类，逐用例隔离：
///拷贝到唯一路径后打开副本。
std::filesystem::path uniqueFixtureJar()
{
    static int counter = 0;
    const auto source  = writeFixture();
    auto       target  = source;
    target.replace_filename("mjt_lvt_display_" + std::to_string(++counter) + ".jar");
    std::filesystem::copy_file(source, target, std::filesystem::copy_options::overwrite_existing);
    return target;
}

///非法形态名（控制字符开头；char 字面量拼接避开转义贪吃）。
std::string ctrlName(const char* suffix)
{
    return std::string(1, '\x01') + suffix;
}

///locals 数组 → 名字列表（断言面友好）。
std::vector<std::string> localNames(const Json& method)
{
    std::vector<std::string> names;
    for (const auto& local : method.at("locals")) names.push_back(local.at("name").get<std::string>());
    return names;
}

///class_query kind=bytes 的 base64 content → 原始字节（与 mcp_shadow_token_test
///同一解码口径）。
std::vector<ca::u8> decodedClassBytes(McpSessionHarness& server, const std::string& projectId)
{
    const auto bytes = call(server,
                            "class_query",
                            {{"project_id", projectId}, {"kind", "bytes"}, {"class", "mcp/Subject"}});
    EXPECT_FALSE(bytes.at("result").at("isError")) << bytes.dump();
    const auto& encoded = payload(bytes).at("content").get_ref<const std::string&>();
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<ca::u8> decoded;
    int                 buffer = 0;
    int                 bits   = 0;
    for (const char c : encoded) {
        if (c == '=' || alphabet.find(c) == std::string::npos) continue;
        buffer = (buffer << 6) | static_cast<int>(alphabet.find(c));
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<ca::u8>((buffer >> bits) & 0xFF));
        }
    }
    return decoded;
}

}   // namespace

TEST(McpLvtDisplayTest, MethodGetKeepsValidLocalNameWhenJarIsTrustworthy)
{
    // jar 仅 1 行合法名（0/1 < 1/2）：不兜底 → 合法名原样透出。
    McpSessionHarness server;
    const auto        jar       = uniqueFixtureJar();
    const auto        opened    = call(server, "project_open", {{"path", jar.string()}});
    ASSERT_FALSE(opened.at("result").at("isError")) << opened.dump();
    const auto projectId = payload(opened).at("project_id").get<std::string>();

    const auto patch = call(server,
                            "edit_apply",
                            {{"project_id", projectId},
                             {"kind", "structured"},
                             {"class_uri", "mcp/Subject.class"},
                             {"mutation_kind", "replace_method_body"},
                             {"member_name", "value"},
                             {"member_descriptor", "()I"},
                             {"initial_instructions",
                              Json::array({{{"kind", "label"}, {"label", "Ls"}},
                                           {{"kind", "int"}, {"opcode", 16}, {"operand", 7}},
                                           {{"kind", "var"}, {"opcode", 54}, {"operand", 0}},
                                           {{"kind", "var"}, {"opcode", 21}, {"operand", 0}},
                                           {{"kind", "label"}, {"label", "Le"}},
                                           {{"kind", "simple"}, {"opcode", 172}}})},
                             {"local_variables",
                              Json::array({Json{{"name", "held"},
                                                {"descriptor", "I"},
                                                {"start_label", "Ls"},
                                                {"end_label", "Le"},
                                                {"index", 0}}})}});
    ASSERT_FALSE(patch.at("result").at("isError")) << patch.dump();

    const auto method = call(server,
                             "class_query",
                             {{"project_id", projectId},
                              {"kind", "method"},
                              {"owner", "mcp/Subject"},
                              {"name", "value"},
                              {"descriptor", "()I"}});
    ASSERT_FALSE(method.at("result").at("isError")) << method.dump();
    EXPECT_EQ(std::vector<std::string>{"held"}, localNames(payload(method)));
}

TEST(McpLvtDisplayTest, MethodGetFallsBackToVarSlotWhenJarNamesMostlyInvalid)
{
    // jar 共 3 行、2 行非法 = 2/3 ≥ 1/2：jar 级兜底 → 合法名一并 var<槽位号>；
    // 呈现层替换不回写，class_query kind=bytes 仍见原始名字字节。
    McpSessionHarness server;
    const auto        jar    = uniqueFixtureJar();
    const auto        opened = call(server, "project_open", {{"path", jar.string()}});
    ASSERT_FALSE(opened.at("result").at("isError")) << opened.dump();
    const auto projectId = payload(opened).at("project_id").get<std::string>();

    const auto patch = call(server,
                            "edit_apply",
                            {{"project_id", projectId},
                             {"kind", "structured"},
                             {"class_uri", "mcp/Subject.class"},
                             {"mutation_kind", "replace_method_body"},
                             {"member_name", "value"},
                             {"member_descriptor", "()I"},
                             {"initial_instructions",
                              Json::array({{{"kind", "label"}, {"label", "Ls"}},
                                           {{"kind", "int"}, {"opcode", 16}, {"operand", 7}},
                                           {{"kind", "var"}, {"opcode", 54}, {"operand", 0}},
                                           {{"kind", "var"}, {"opcode", 21}, {"operand", 0}},
                                           {{"kind", "int"}, {"opcode", 16}, {"operand", 9}},
                                           {{"kind", "var"}, {"opcode", 54}, {"operand", 1}},
                                           {{"kind", "var"}, {"opcode", 21}, {"operand", 1}},
                                           {{"kind", "int"}, {"opcode", 16}, {"operand", 11}},
                                           {{"kind", "var"}, {"opcode", 54}, {"operand", 2}},
                                           {{"kind", "var"}, {"opcode", 21}, {"operand", 2}},
                                           {{"kind", "label"}, {"label", "Le"}},
                                           {{"kind", "simple"}, {"opcode", 172}}})},
                             {"local_variables",
                              Json::array({Json{{"name", "held"},
                                                {"descriptor", "I"},
                                                {"start_label", "Ls"},
                                                {"end_label", "Le"},
                                                {"index", 0}},
                                           Json{{"name", ctrlName("a")},
                                                {"descriptor", "I"},
                                                {"start_label", "Ls"},
                                                {"end_label", "Le"},
                                                {"index", 1}},
                                           Json{{"name", ctrlName("b")},
                                                {"descriptor", "I"},
                                                {"start_label", "Ls"},
                                                {"end_label", "Le"},
                                                {"index", 2}}})}});
    ASSERT_FALSE(patch.at("result").at("isError")) << patch.dump();

    const auto method = call(server,
                             "class_query",
                             {{"project_id", projectId},
                              {"kind", "method"},
                              {"owner", "mcp/Subject"},
                              {"name", "value"},
                              {"descriptor", "()I"}});
    ASSERT_FALSE(method.at("result").at("isError")) << method.dump();
    // 兜底全 jar 生效：合法名 held 也呈现 var0；槽位号按物理槽（0/1/2）。
    EXPECT_EQ((std::vector<std::string>{"var0", "var1", "var2"}), localNames(payload(method)));

    // 字节码原文照存：原始名字字节（held / 控制字符名）仍在 class 字节里。
    const auto raw = decodedClassBytes(server, projectId);
    const std::string rawText(reinterpret_cast<const char*>(raw.data()), raw.size());
    EXPECT_NE(std::string::npos, rawText.find("held")) << "original LVT name missing from bytes";
    EXPECT_NE(std::string::npos, rawText.find(ctrlName("a")))
        << "original adversarial LVT name missing from bytes";
}

}   // namespace mjt::mcp
