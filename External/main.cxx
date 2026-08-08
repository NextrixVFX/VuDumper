// simple external ESP for HydroThunder - offset validation only.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Msimg32.lib")

namespace Offsets
{
	constexpr std::uint32_t g_vu_boat_manager = 0x358FB8;
	constexpr std::uint32_t g_vu_viewport_manager = 0x359060;

	constexpr std::uint32_t boat_data = 0x0C;
	constexpr std::uint32_t boat_count = 0x10;

	constexpr std::uint32_t entity_transform = 0x50;
	constexpr std::uint32_t transform_pos = 0x40;

	constexpr std::uint32_t viewport_count = 0x04;
	constexpr std::uint32_t camera0 = 0x28;
	constexpr std::uint32_t camera_stride = 0x274;
	constexpr std::uint32_t cam_proj = 0x30;
	constexpr std::uint32_t cam_forward = 0x140;
	constexpr std::uint32_t cam_up = 0x150;
	constexpr std::uint32_t cam_eye = 0x160;
}

struct Vec3
{
	float x = 0.f, y = 0.f, z = 0.f, pad = 0.f;
};

struct Mat4
{
	float m[16]{};
};

struct BoatSample
{
	std::uint32_t ptr = 0;
	Vec3 pos{};
	bool ok = false;
};

struct CameraSample
{
	Vec3 eye{}, forward{}, up{};
	Mat4 proj{};
	bool ok = false;
};

struct AppState
{
	HANDLE process = nullptr;
	DWORD pid = 0;
	std::uint32_t module_base = 0;
	HWND game_hwnd = nullptr;
	HWND overlay = nullptr;
	bool show_boats = true;
	bool show_hud = true;
	bool running = true;
	CameraSample cam{};
	std::vector<BoatSample> boats{};
	std::string status{};

	int overlay_x = 0, overlay_y = 0, overlay_w = 0, overlay_h = 0;
	int view_x = 0, view_y = 0, view_w = 0, view_h = 0;
};

static AppState g{};

static bool rpm(std::uint32_t addr, void* out, std::size_t size)
{
	SIZE_T n = 0;
	return g.process
		&& ReadProcessMemory(g.process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)), out, size, &n)
		&& n == size;
}

static bool read_u32(std::uint32_t addr, std::uint32_t& out)
{
	return rpm(addr, &out, sizeof(out));
}

static bool read_vec3(std::uint32_t addr, Vec3& out)
{
	return rpm(addr, &out, sizeof(out));
}

static bool read_mat4(std::uint32_t addr, Mat4& out)
{
	return rpm(addr, &out, sizeof(out));
}

static DWORD find_pid(const wchar_t* name)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe{ sizeof(pe) };
	DWORD pid = 0;
	if (Process32FirstW(snap, &pe))
	{
		do
		{
			if (_wcsicmp(pe.szExeFile, name) == 0)
			{
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return pid;
}

static std::uint32_t find_module_base(DWORD pid, const wchar_t* module_name)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32W me{ sizeof(me) };
	std::uint32_t base = 0;
	if (Module32FirstW(snap, &me))
	{
		do
		{
			if (_wcsicmp(me.szModule, module_name) == 0)
			{
				base = static_cast<std::uint32_t>(reinterpret_cast<uintptr_t>(me.modBaseAddr));
				break;
			}
		} while (Module32NextW(snap, &me));
	}
	CloseHandle(snap);
	return base;
}

struct EnumCtx
{
	DWORD pid = 0;
	HWND hwnd = nullptr;
};

static BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lp)
{
	auto* ctx = reinterpret_cast<EnumCtx*>(lp);
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid != ctx->pid || !IsWindowVisible(hwnd))
		return TRUE;

	wchar_t title[256]{};
	GetWindowTextW(hwnd, title, 256);
	if (title[0] == L'\0')
		return TRUE;

	ctx->hwnd = hwnd;
	return FALSE;
}

static HWND find_game_window(DWORD pid)
{
	EnumCtx ctx{ pid, nullptr };
	EnumWindows(enum_windows_cb, reinterpret_cast<LPARAM>(&ctx));
	return ctx.hwnd;
}

static bool attach(const wchar_t* process_name)
{
	g.pid = find_pid(process_name);
	if (!g.pid)
	{
		g.status = "process not found — start HydroThunder.exe";
		return false;
	}

	g.process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, g.pid);
	if (!g.process)
	{
		char buf[96]{};
		std::snprintf(buf, sizeof(buf), "OpenProcess failed (%lu) — run as admin?", GetLastError());
		g.status = buf;
		return false;
	}

	g.module_base = find_module_base(g.pid, process_name);
	if (!g.module_base)
	{
		g.status = "module base not found";
		return false;
	}

	g.game_hwnd = find_game_window(g.pid);
	char buf[128]{};
	std::snprintf(buf, sizeof(buf), "attached pid=%lu base=0x%08X", g.pid, g.module_base);
	g.status = buf;
	return true;
}

static void refresh_camera()
{
	g.cam = {};
	std::uint32_t mgr = 0;
	if (!read_u32(g.module_base + Offsets::g_vu_viewport_manager, mgr) || !mgr)
		return;

	std::uint32_t count = 0;
	(void)read_u32(mgr + Offsets::viewport_count, count);
	if (count == 0 || count > 4)
		count = 1;

	const std::uint32_t cam = mgr + Offsets::camera0; // viewport 0
	if (!read_vec3(cam + Offsets::cam_eye, g.cam.eye)
		|| !read_vec3(cam + Offsets::cam_forward, g.cam.forward)
		|| !read_vec3(cam + Offsets::cam_up, g.cam.up))
		return;

	(void)read_mat4(cam + Offsets::cam_proj, g.cam.proj);
	g.cam.ok = true;
}

static void refresh_boats()
{
	g.boats.clear();
	std::uint32_t mgr = 0;
	if (!read_u32(g.module_base + Offsets::g_vu_boat_manager, mgr) || !mgr)
		return;

	std::uint32_t data = 0, count = 0;
	if (!read_u32(mgr + Offsets::boat_data, data) || !read_u32(mgr + Offsets::boat_count, count))
		return;
	if (!data || count == 0 || count > 32)
		return;

	g.boats.reserve(count);
	for (std::uint32_t i = 0; i < count; ++i)
	{
		BoatSample b{};
		if (!read_u32(data + i * 4, b.ptr) || !b.ptr)
		{
			g.boats.push_back(b);
			continue;
		}

		std::uint32_t xf = 0;
		if (!read_u32(b.ptr + Offsets::entity_transform, xf) || !xf)
		{
			g.boats.push_back(b);
			continue;
		}

		if (read_vec3(xf + Offsets::transform_pos, b.pos))
			b.ok = true;
		g.boats.push_back(b);
	}
}

static float len3(float x, float y, float z)
{
	return std::sqrt(x * x + y * y + z * z);
}

static void normalize3(float& x, float& y, float& z)
{
	const float L = len3(x, y, z);
	if (L < 1e-6f)
		return;
	x /= L;
	y /= L;
	z /= L;
}

// Z-up W2S from validated eye / forward / up. Depth along forward.
static bool world_to_screen(const Vec3& world, float width, float height, float& sx, float& sy, float& depth)
{
	if (!g.cam.ok)
		return false;

	float fx = g.cam.forward.x, fy = g.cam.forward.y, fz = g.cam.forward.z;
	float ux = g.cam.up.x, uy = g.cam.up.y, uz = g.cam.up.z;
	normalize3(fx, fy, fz);
	normalize3(ux, uy, uz);

	// right = forward × up  (Z-up chase camera)
	float rx = fy * uz - fz * uy;
	float ry = fz * ux - fx * uz;
	float rz = fx * uy - fy * ux;
	normalize3(rx, ry, rz);

	// re-orthogonalize up
	ux = ry * fz - rz * fy;
	uy = rz * fx - rx * fz;
	uz = rx * fy - ry * fx;
	normalize3(ux, uy, uz);

	const float dx = world.x - g.cam.eye.x;
	const float dy = world.y - g.cam.eye.y;
	const float dz = world.z - g.cam.eye.z;

	const float cx = dx * rx + dy * ry + dz * rz;
	const float cy = dx * ux + dy * uy + dz * uz;
	const float cz = dx * fx + dy * fy + dz * fz; // depth
	depth = cz;
	if (cz < 1.f)
		return false;

	// Prefer FOV from proj[0] if it looks like a perspective scale; else ~70°.
	float fov_scale = 1.428f; // ~1 / tan(35°)
	const float p00 = g.cam.proj.m[0];
	if (std::isfinite(p00) && p00 > 0.2f && p00 < 5.f)
		fov_scale = p00;

	const float aspect = width / (height > 1.f ? height : 1.f);
	sx = (width * 0.5f) + (cx / cz) * fov_scale * (height * 0.5f) * (aspect >= 1.f ? 1.f : aspect);
	sy = (height * 0.5f) - (cy / cz) * fov_scale * (height * 0.5f);
	return sx >= -50.f && sy >= -50.f && sx <= width + 50.f && sy <= height + 50.f;
}

static void sync_overlay_fullscreen()
{
	if (!g.overlay)
		return;

	if (!g.game_hwnd || !IsWindow(g.game_hwnd))
		g.game_hwnd = find_game_window(g.pid);

	const HWND anchor = g.game_hwnd ? g.game_hwnd : GetDesktopWindow();
	HMONITOR mon = MonitorFromWindow(anchor, MONITOR_DEFAULTTOPRIMARY);
	MONITORINFO mi{ sizeof(mi) };
	if (!GetMonitorInfoW(mon, &mi))
		return;

	g.overlay_x = mi.rcMonitor.left;
	g.overlay_y = mi.rcMonitor.top;
	g.overlay_w = mi.rcMonitor.right - mi.rcMonitor.left;
	g.overlay_h = mi.rcMonitor.bottom - mi.rcMonitor.top;

	g.view_x = 0;
	g.view_y = 0;
	g.view_w = g.overlay_w;
	g.view_h = g.overlay_h;

	if (g.game_hwnd)
	{
		RECT client{};
		if (GetClientRect(g.game_hwnd, &client))
		{
			POINT tl{ client.left, client.top };
			POINT br{ client.right, client.bottom };
			ClientToScreen(g.game_hwnd, &tl);
			ClientToScreen(g.game_hwnd, &br);
			g.view_x = tl.x - g.overlay_x;
			g.view_y = tl.y - g.overlay_y;
			g.view_w = br.x - tl.x;
			g.view_h = br.y - tl.y;
			if (g.view_w < 1) g.view_w = g.overlay_w;
			if (g.view_h < 1) g.view_h = g.overlay_h;
		}
	}

	SetWindowPos(
		g.overlay,
		HWND_TOPMOST,
		g.overlay_x,
		g.overlay_y,
		g.overlay_w,
		g.overlay_h,
		SWP_NOACTIVATE);
}

static void paint(HWND hwnd)
{
	PAINTSTRUCT ps{};
	HDC hdc = BeginPaint(hwnd, &ps);
	RECT rc{};
	GetClientRect(hwnd, &rc);
	const int w = rc.right - rc.left;
	const int h = rc.bottom - rc.top;

	HDC mem = CreateCompatibleDC(hdc);
	HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
	HGDIOBJ old = SelectObject(mem, bmp);

	HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
	FillRect(mem, &rc, bg);
	DeleteObject(bg);

	SetBkMode(mem, TRANSPARENT);

	const int hud_x = (g.view_x > 0 ? g.view_x : 0) + 12;
	const int hud_y = (g.view_y > 0 ? g.view_y : 0) + 10;

	if (g.show_hud)
	{
		SetTextColor(mem, RGB(0, 255, 120));
		char line[256]{};
		std::snprintf(line, sizeof(line),
			"External fullscreen %dx%d | %s | boats=%zu  [F1 boats] [F2 hud] [END quit]",
			g.overlay_w, g.overlay_h, g.status.c_str(), g.boats.size());
		TextOutA(mem, hud_x, hud_y, line, static_cast<int>(std::strlen(line)));

		if (g.cam.ok)
		{
			std::snprintf(line, sizeof(line),
				"eye (%.1f, %.1f, %.1f)  fwd (%.2f, %.2f, %.2f)",
				g.cam.eye.x, g.cam.eye.y, g.cam.eye.z,
				g.cam.forward.x, g.cam.forward.y, g.cam.forward.z);
			TextOutA(mem, hud_x, hud_y + 18, line, static_cast<int>(std::strlen(line)));
		}
		else
		{
			const char* miss = "camera read FAILED — check viewport manager / camera offsets";
			SetTextColor(mem, RGB(255, 80, 80));
			TextOutA(mem, hud_x, hud_y + 18, miss, static_cast<int>(std::strlen(miss)));
			SetTextColor(mem, RGB(0, 255, 120));
		}
	}

	if (g.show_boats)
	{
		HPEN pen = CreatePen(PS_SOLID, 2, RGB(0, 220, 255));
		HGDIOBJ old_pen = SelectObject(mem, pen);
		HBRUSH null_brush = (HBRUSH)GetStockObject(NULL_BRUSH);
		HGDIOBJ old_brush = SelectObject(mem, null_brush);
		SetTextColor(mem, RGB(255, 255, 0));

		const float vw = static_cast<float>(g.view_w > 0 ? g.view_w : w);
		const float vh = static_cast<float>(g.view_h > 0 ? g.view_h : h);

		int drawn = 0;
		for (std::size_t i = 0; i < g.boats.size(); ++i)
		{
			const auto& b = g.boats[i];
			if (!b.ok)
				continue;

			float sx = 0.f, sy = 0.f, depth = 0.f;
			if (!world_to_screen(b.pos, vw, vh, sx, sy, depth))
				continue;

			const int x = static_cast<int>(sx) + g.view_x;
			const int y = static_cast<int>(sy) + g.view_y;
			const int box = 18;
			Rectangle(mem, x - box, y - box, x + box, y + box);
			MoveToEx(mem, x - 6, y, nullptr);
			LineTo(mem, x + 6, y);
			MoveToEx(mem, x, y - 6, nullptr);
			LineTo(mem, x, y + 6);

			char label[96]{};
			std::snprintf(label, sizeof(label), "boat%zu  %.0f,%.0f,%.0f", i, b.pos.x, b.pos.y, b.pos.z);
			TextOutA(mem, x + box + 4, y - 8, label, static_cast<int>(std::strlen(label)));
			++drawn;
		}

		if (g.show_hud)
		{
			char line[96]{};
			std::snprintf(line, sizeof(line), "on-screen boats: %d", drawn);
			TextOutA(mem, hud_x, hud_y + 36, line, static_cast<int>(std::strlen(line)));

			int row = hud_y + 54;
			for (std::size_t i = 0; i < g.boats.size() && i < 8; ++i)
			{
				const auto& b = g.boats[i];
				std::snprintf(line, sizeof(line), "[%zu] ptr=0x%08X %s (%.1f, %.1f, %.1f)",
					i, b.ptr, b.ok ? "ok" : "bad", b.pos.x, b.pos.y, b.pos.z);
				TextOutA(mem, hud_x, row, line, static_cast<int>(std::strlen(line)));
				row += 16;
			}
		}

		SelectObject(mem, old_brush);
		SelectObject(mem, old_pen);
		DeleteObject(pen);
	}

	BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
	SelectObject(mem, old);
	DeleteObject(bmp);
	DeleteDC(mem);
	EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_PAINT:
		paint(hwnd);
		return 0;
	case WM_ERASEBKGND:
		return 1;
	case WM_DESTROY:
		g.running = false;
		PostQuitMessage(0);
		return 0;
	default:
		return DefWindowProcW(hwnd, msg, wp, lp);
	}
}

static HWND create_overlay(HINSTANCE inst)
{
	WNDCLASSEXW wc{ sizeof(wc) };
	wc.lpfnWndProc = wnd_proc;
	wc.hInstance = inst;
	wc.lpszClassName = L"VuExternalOverlay";
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	RegisterClassExW(&wc);

	const int sw = GetSystemMetrics(SM_CXSCREEN);
	const int sh = GetSystemMetrics(SM_CYSCREEN);

	HWND hwnd = CreateWindowExW(
		WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
		wc.lpszClassName,
		L"External",
		WS_POPUP,
		0, 0, sw, sh,
		nullptr, nullptr, inst, nullptr);

	SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
	ShowWindow(hwnd, SW_SHOWNOACTIVATE);
	return hwnd;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int)
{
	AllocConsole();
	FILE* fp = nullptr;
	freopen_s(&fp, "CONOUT$", "w", stdout);

	std::printf("External — HydroThunder offset check\n");
	std::printf("Waiting for HydroThunder.exe...\n");

	while (!attach(L"HydroThunder.exe"))
	{
		std::printf("\r%s          ", g.status.c_str());
		Sleep(500);
		if (GetAsyncKeyState(VK_END) & 1)
			return 0;
	}
	std::printf("\n%s\n", g.status.c_str());

	g.overlay = create_overlay(inst);
	if (!g.overlay)
		return 1;

	MSG msg{};
	while (g.running)
	{
		while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
		{
			if (msg.message == WM_QUIT)
				g.running = false;
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}

		if (GetAsyncKeyState(VK_END) & 1)
			break;
		if (GetAsyncKeyState(VK_F1) & 1)
			g.show_boats = !g.show_boats;
		if (GetAsyncKeyState(VK_F2) & 1)
			g.show_hud = !g.show_hud;

		if (!g.process)
			break;

		DWORD code = 0;
		if (!GetExitCodeProcess(g.process, &code) || code != STILL_ACTIVE)
		{
			g.status = "process exited";
			break;
		}

		refresh_camera();
		refresh_boats();
		sync_overlay_fullscreen();
		InvalidateRect(g.overlay, nullptr, FALSE);
		Sleep(16);
	}

	if (g.process)
		CloseHandle(g.process);
	if (g.overlay)
		DestroyWindow(g.overlay);
	return 0;
}
