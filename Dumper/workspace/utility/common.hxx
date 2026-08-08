#pragma once

namespace Dumper::Common
{
	static inline std::string to_lower(std::string value)
	{
		std::transform(value.begin(), value.end(), value.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return value;
	}

	static inline std::string sanitize_identifier(std::string_view name)
	{
		std::string out;
		out.reserve(name.size());

		for (char c : name)
		{
			if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
				out.push_back(c);
			else if (c == ' ' || c == '-' || c == '/' || c == '@' || c == ':' || c == '<' || c == '>' || c == '$' || c == '?')
				out.push_back('_');
		}

		// collapse repeats
		out.erase(std::unique(out.begin(), out.end(),
			[](char a, char b) { return a == '_' && b == '_'; }), out.end());
		while (!out.empty() && out.back() == '_')
			out.pop_back();

		if (out.empty())
			out = "unnamed";

		if (std::isdigit(static_cast<unsigned char>(out.front())))
			out.insert(out.begin(), '_');

		return out;
	}

	static inline bool starts_with(std::string_view value, std::string_view prefix)
	{
		return value.size() >= prefix.size()
			&& value.compare(0, prefix.size(), prefix) == 0;
	}

	static inline bool ends_with(std::string_view value, std::string_view suffix)
	{
		return value.size() >= suffix.size()
			&& value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
	}

	[[nodiscard]] static inline bool path_looks_protected(const std::filesystem::path& path)
	{
		const auto s = to_lower(path.string());
		return s.find("\\windowsapps\\") != std::string::npos
			|| s.find("/windowsapps/") != std::string::npos
			|| s.find("\\program files\\") != std::string::npos
			|| s.find("\\program files (x86)\\") != std::string::npos;
	}

	// Candidate output folder beside the image. Does not create directories (may be unwritable).
	[[nodiscard]] static inline std::filesystem::path default_output_dir(const std::filesystem::path& input_path)
	{
		const auto stem = input_path.stem().string();
		return input_path.parent_path() / (stem + "_sdk");
	}

	[[nodiscard]] static inline std::filesystem::path cwd_output_dir(const std::filesystem::path& input_path)
	{
		std::error_code ec;
		auto cwd = std::filesystem::current_path(ec);
		if (ec)
			cwd = ".";
		return cwd / (input_path.stem().string() + "_sdk");
	}

	// Create out dir if possible; on protected/unwritable image locations fall back to cwd.
	[[nodiscard]] static inline std::filesystem::path make_output_dir(const std::filesystem::path& input_path)
	{
		std::error_code ec;
		std::filesystem::path out = default_output_dir(input_path);

		if (path_looks_protected(input_path) || path_looks_protected(out))
			out = cwd_output_dir(input_path);

		std::filesystem::create_directories(out, ec);
		if (ec)
		{
			out = cwd_output_dir(input_path);
			ec.clear();
			std::filesystem::create_directories(out, ec);
		}

		return out;
	}

	static inline std::string demangle_msvc_class_name(std::string_view mangled)
	{
		// ".?AVVuBoatEntity@@" / ".?AUSomeStruct@@" / ".?AV?$VuAssetProperty@VVuTextureAsset@@@@"
		if (!starts_with(mangled, ".?A") || mangled.size() < 5)
			return {};

		size_t start = 4; // skip ".?AV" / ".?AU"
		if (mangled[3] != 'V' && mangled[3] != 'U')
			return {};

		std::string_view body = mangled.substr(start);
		if (ends_with(body, "@@"))
			body.remove_suffix(2);

		// Keep template names readable-ish.
		return std::string(body);
	}
}
