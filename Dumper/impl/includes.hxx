#pragma once

#define WIN32_LEAN_AND_MEAN

#ifdef _MSC_VER
#pragma warning(disable: 4996)
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
#pragma warning(disable: 4005)
#pragma warning(disable: 4099)
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <format>
#include <utility>
#include <optional>
#include <cmath>
#include <iomanip>

#pragma comment(lib, "Psapi.lib")

#include <impl/include/hexrays/hexrays.h>

#include <workspace/utility/logger.hxx>
#include <workspace/utility/common.hxx>
#include <workspace/utility/target.hxx>

#include <workspace/core/parsing/image.hxx>
#include <workspace/core/parsing/types.hxx>

#include <workspace/core/reflection/rtti.hxx>
#include <workspace/core/reflection/properties.hxx>
#include <workspace/core/reflection/globals.hxx>

#include <workspace/core/model/engine_model.hxx>
#include <workspace/core/live/live.hxx>
#include <workspace/core/emission/emitter.hxx>
#include <workspace/core/dumper.hxx>

using namespace Dumper;
using namespace Dumper::Common;
using namespace Dumper::Types;
