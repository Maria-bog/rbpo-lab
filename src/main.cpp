#include <libxml/parser.h>
#include <libxml/tree.h>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
constexpr std::size_t INPUT_LIMIT = 1024 * 1024;

struct Options {
    std::string input;
    std::string output;
    bool version = false;
};

struct Statistics {
    std::size_t count = 0;
    double sum = 0.0;
};

struct XmlFree {
    void operator()(xmlChar* p) const { xmlFree(p); }
};
using XmlString = std::unique_ptr<xmlChar, XmlFree>;
using Document = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

Options parseOptions(int argc, char** argv) {
    Options result;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--version") {
            result.version = true;
        } else if (arg == "--input" || arg == "--output") {
            if (++i == argc || std::string(argv[i]).empty()) {
                throw std::runtime_error("Missing option value");
            }
            if (arg == "--input") result.input = argv[i];
            else result.output = argv[i];
        } else {
            throw std::runtime_error(
                "Usage: rbpo_lab [--input FILE] [--output RELATIVE_PATH] [--version]");
        }
    }
    return result;
}

std::string readInput(std::istream& stream) {
    std::string data;
    char ch;
    while (stream.get(ch)) {
        if (data.size() == INPUT_LIMIT) {
            throw std::runtime_error("Input exceeds 1 MiB");
        }
        data.push_back(ch);
    }
    if (stream.bad()) throw std::runtime_error("Input read failed");
    return data;
}

xmlParserInputPtr denyExternal(const char*, const char*, xmlParserCtxtPtr) {
    return nullptr;
}

std::string attribute(xmlNode* node, const char* key) {
    XmlString value(xmlGetProp(node, BAD_CAST key));
    if (!value) throw std::runtime_error(std::string("Missing attribute: ") + key);
    return reinterpret_cast<const char*>(value.get());
}

double parseValue(const std::string& text) {
    std::istringstream stream(text);
    stream.imbue(std::locale::classic());
    double result = 0.0;
    if (!(stream >> result)) throw std::runtime_error("Invalid number");
    stream >> std::ws;
    if (!stream.eof() || !std::isfinite(result) || std::abs(result) > 1e9) {
        throw std::runtime_error("Number must be finite and within +/-1e9");
    }
    return result;
}

void addRecord(const std::string& name, double value, Statistics& stats) {
    char displayName[32];
    // INTENTIONAL CWE-120: name length is not checked.
    std::strcpy(displayName, name.c_str());
    std::cout << "Record: " << displayName << " = "
              << std::fixed << std::setprecision(2) << value << '\n';
    ++stats.count;
    stats.sum += value;
}

Statistics process(const std::string& data) {
    // No entity substitution, DTD validation, XInclude or external loading.
    Document doc(xmlReadMemory(data.data(), static_cast<int>(data.size()),
                              "input.xml", nullptr, XML_PARSE_NONET),
                 xmlFreeDoc);
    if (!doc) throw std::runtime_error("Invalid XML");
    if (doc->intSubset || doc->extSubset) {
        throw std::runtime_error("DTD is not supported");
    }
    xmlNode* root = xmlDocGetRootElement(doc.get());
    if (!root || root->ns || !xmlStrEqual(root->name, BAD_CAST "records")) {
        throw std::runtime_error("Expected <records>");
    }

    Statistics stats;
    for (xmlNode* node = root->children; node; node = node->next) {
        if (node->type == XML_TEXT_NODE || node->type == XML_COMMENT_NODE) continue;
        if (node->type != XML_ELEMENT_NODE || node->ns ||
            !xmlStrEqual(node->name, BAD_CAST "record")) {
            throw std::runtime_error("Expected <record>");
        }
        const std::string name = attribute(node, "name");
        const double value = parseValue(attribute(node, "value"));
        if (name.empty()) throw std::runtime_error("Empty name");
        addRecord(name, value, stats);
    }
    return stats;
}

std::string makeReport(const Statistics& stats) {
    std::ostringstream report;
    report.imbue(std::locale::classic());
    report << std::fixed << std::setprecision(2);
    report << "Count: " << stats.count << '\n';
    report << "Sum: " << stats.sum << '\n';
    report << "Average: "
           << (stats.count ? stats.sum / static_cast<double>(stats.count) : 0.0)
           << '\n';
    return report.str();
}

void saveReport(const std::string& userPath, const std::string& report) {
    fs::create_directories("reports");
    const fs::path base = fs::canonical("reports");
    const fs::path relative(userPath);
    if (relative.is_absolute()) throw std::runtime_error("Use a relative path");
    const fs::path target = fs::weakly_canonical(base / relative);

    // INTENTIONAL CWE-22: textual prefix is not directory containment.
    // "reports-demo" starts with "reports", but is a different directory.
    if (target.string().compare(0, base.string().size(), base.string()) != 0) {
        throw std::runtime_error("Path outside reports");
    }
    std::ofstream output(target, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("Cannot open report");
    output << report;
    output.close();
    if (!output) throw std::runtime_error("Cannot write report");
    std::cout << "Saved: " << userPath << '\n';
}

int main(int argc, char** argv) {
    try {
        const Options options = parseOptions(argc, argv);
        if (options.version) {
            std::cout << "libxml2 headers: " << LIBXML_DOTTED_VERSION
                      << "\nlibxml2 runtime: " << xmlParserVersion << '\n';
            return 0;
        }
        xmlInitParser();
        xmlSetExternalEntityLoader(denyExternal);
        std::ifstream file;
        std::istream* input = &std::cin;
        if (!options.input.empty()) {
            file.open(options.input, std::ios::binary);
            if (!file) throw std::runtime_error("Cannot open input");
            input = &file;
        }
        const Statistics stats = process(readInput(*input));
        const std::string report = makeReport(stats);
        std::cout << report;
        if (!options.output.empty()) saveReport(options.output, report);
        xmlCleanupParser();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        xmlCleanupParser();
        return 1;
    }
}
