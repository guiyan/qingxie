import dataclasses
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend as b


class Package:
    def __init__(self, name="vlc", essential=False, priority="optional", protected="no", delete=True):
        self.name = name
        self.fullname = name + ":amd64"
        self.essential = essential
        self.marked_delete = delete
        self.is_installed = True
        self.installed = SimpleNamespace(priority=priority, record={"Protected": protected}, version="1", installed_size=1024)
        self._pkg = SimpleNamespace(selected_state=1)

    def mark_delete(self, **kwargs):
        self.options = kwargs


class Cache(dict):
    broken_count = 0

    def get_changes(self):
        return list(self.values())


class BackendTests(unittest.TestCase):
    def test_apt_size_metadata(self):
        cases = {"52": 53248, "52K": 53248, " 52 KiB ": 53248,
                 "1.5M": 1572864, "2 MB": 2000000, "2g": 2147483648,
                 "7B": 7, "": 0, "unknown": 0, "-1": 0,
                 "52Kjunk": 0, "1.2.3": 0}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(b.apt_size_bytes(value), expected)

    def test_apt_scan_survives_nonstandard_and_invalid_sizes(self):
        rows = "".join(f"{name}\tii \t{size}\t1\tno\toptional\tno\n"
                       for name, size in [("normal", "100"), ("suffix", "52K"),
                                          ("bad", "invalid"), ("last", "20")])
        with patch.object(b, "run", return_value=SimpleNamespace(stdout=rows)), \
             patch.object(b.Path, "glob", return_value=[]):
            apps = b.list_apt(all_packages=True)
        self.assertEqual({a.id: a.size for a in apps},
                         {"normal": 102400, "suffix": 53248, "bad": 0, "last": 20480})

    def test_rejects_option_and_shell_injection(self):
        for source, ident in [("APT", "--allow-remove-essential"), ("APT", "vlc;touch /tmp/x"),
                              ("APT", "vlc*"), ("Snap", "../snapd"), ("Flatpak", "--all"),
                              ("Flatpak", "runtime/org.gnome.Platform/x86_64/47")]:
            with self.subTest(ident=ident), self.assertRaises(b.BackendError):
                b.validate_id(source, ident)

    def test_valid_multiarch_and_full_ref(self):
        b.validate_id("APT", "libx11-6:amd64")
        b.validate_id("Flatpak", "app/org.gnome.Calculator/x86_64/stable", "user")

    def test_apt_includes_all_removals_and_versions(self):
        c = Cache(vlc=Package(), addon=Package("addon"))
        result = b.apt_plan("vlc", True, c)
        self.assertEqual([x["id"] for x in result], ["addon:amd64", "vlc:amd64"])
        self.assertTrue(c["vlc"].options["purge"])

    def test_apt_blocks_protected_dependencies(self):
        for pkg in (Package("dep", essential=True), Package("dep", protected="yes"),
                    Package("dep", priority="important"), Package("gnome-shell")):
            with self.subTest(pkg=pkg.name), self.assertRaises(b.BackendError):
                b.apt_plan("vlc", cache=Cache(vlc=Package(), dep=pkg))

    def test_apt_blocks_installs_and_holds(self):
        with self.assertRaises(b.BackendError):
            b.apt_plan("vlc", cache=Cache(vlc=Package(), dep=Package(delete=False)))
        p = Package()
        p._pkg.selected_state = 2
        with self.assertRaises(b.BackendError):
            b.apt_plan("vlc", cache=Cache(vlc=p))

    def test_apt_blocks_broken_or_missing(self):
        c = Cache(vlc=Package())
        c.broken_count = 1
        with self.assertRaises(b.BackendError):
            b.apt_plan("vlc", cache=c)
        with self.assertRaises(b.BackendError):
            b.apt_plan("missing", cache=Cache())

    def test_flatpak_exact_scope_and_ref_preserves_data(self):
        p = {"id": "app/org.gnome.Calculator/x86_64/stable", "scope": "user", "delete_data": False}
        cmd = b.flatpak_command(p)
        self.assertIn("--user", cmd)
        self.assertIn("--no-related", cmd)
        self.assertNotIn("--delete-data", cmd)
        self.assertEqual(cmd[-1], p["id"])

    def test_flatpak_shared_user_data_is_protected(self):
        a = b.App("app/org.gnome.Calculator/x86_64/stable", "Calc", "Flatpak", scope="user")
        other = dataclasses.replace(a, scope="system")
        with patch.object(b, "list_flatpak", return_value=[a, other]), self.assertRaises(b.BackendError):
            b.plan(a, delete_data=True)

    def test_revalidation_detects_version_change(self):
        old = {"id": "vlc", "name": "VLC", "source": "APT", "scope": "system", "purge": False,
               "delete_data": False, "fingerprint": "old"}
        with patch.object(b, "plan", return_value={"fingerprint": "new"}), self.assertRaises(b.BackendError):
            b.revalidate(old)

    def test_snapshot_failure_prevents_snap_removal(self):
        p = {"source": "Snap", "id": "obs-studio", "scope": "system"}
        with patch.object(b.os, "geteuid", return_value=0), patch.object(b, "revalidate"), \
             patch.object(b.subprocess, "call", return_value=1) as call, self.assertRaises(b.BackendError):
            b.privileged_apply(p)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0], ["/usr/bin/snap", "save", "obs-studio"])

    def test_snap_save_precedes_remove(self):
        p = {"source": "Snap", "id": "obs-studio", "scope": "system"}
        with patch.object(b.os, "geteuid", return_value=0), patch.object(b, "revalidate"), \
             patch.object(b.subprocess, "call", return_value=0) as call:
            b.privileged_apply(p)
        self.assertEqual([c.args[0][1] for c in call.call_args_list], ["save", "remove"])

    def test_unprivileged_helper_refuses(self):
        with patch.object(b.os, "geteuid", return_value=1000), self.assertRaises(b.BackendError):
            b.privileged_apply({})

    def test_size_units(self):
        self.assertEqual(b.size_bytes("1.5 GB"), 1500000000)
        self.assertEqual(b.size_bytes("2 MiB"), 2097152)
        self.assertEqual(b.size_bytes("unknown"), 0)

    def test_flatpak_uses_declared_icon_instead_of_guessing_app_id(self):
        output = SimpleNamespace(stdout="org.example.App/x86_64/stable\tApp\t1\t10 MB\n")
        with patch.object(b.Path, "exists", return_value=True), \
             patch.object(b, "run", return_value=output), \
             patch.object(b, "desktop_meta", return_value=("App", "custom-app-icon", "")) as meta:
            apps = b.list_flatpak()
        self.assertEqual([a.icon for a in apps], ["custom-app-icon", "custom-app-icon"])
        self.assertEqual({a.scope for a in apps}, {"user", "system"})
        self.assertTrue(all(str(c.args[0]).endswith("org.example.App.desktop") for c in meta.call_args_list))

    def test_desktop_without_owner_is_attributed_by_exec(self):
        """装到 /opt 的应用会把 .desktop 手工拷进菜单目录，dpkg 不认这份拷贝，
        只按文件归属判定的话整个应用会从列表里消失（qianwen、douyin）。"""
        desktop = Path("/usr/share/applications/douyin.desktop")
        binary = "/opt/apps/com.douyin.otohime/files/douyin"

        def owners(paths):
            paths = [str(p) for p in paths]
            return {binary: "com.douyin.otohime"} if binary in paths else {}

        with patch.object(b, "desktop_dirs", return_value=[Path("/usr/share/applications")]), \
             patch.object(b.Path, "is_dir", return_value=True), \
             patch.object(b.Path, "glob", return_value=[desktop]), \
             patch.object(b.Path, "is_file", return_value=True), \
             patch.object(b, "desktop_exec", return_value=binary), \
             patch.object(b, "dpkg_owners", side_effect=owners):
            files, attributed, loose = b.attribute_desktops({})
        self.assertEqual(files, [desktop])
        self.assertEqual(attributed, {str(desktop): "com.douyin.otohime"})
        self.assertEqual(loose, {str(desktop)})

    def test_bare_exec_falls_back_to_matching_the_packages_own_entry(self):
        """Exec=firefox %U 是 PATH 上的裸命令，反查不到包；但菜单目录里那份
        副本和包自带的入口同名，够用了。"""
        desktop = Path("/usr/share/applications/firefox-spark.desktop")
        index = {"firefox-spark": ["/opt/apps/firefox-spark/entries/applications/firefox-spark.desktop"]}
        with patch.object(b, "desktop_dirs", return_value=[Path("/usr/share/applications")]), \
             patch.object(b.Path, "is_dir", return_value=True), \
             patch.object(b.Path, "glob", return_value=[desktop]), \
             patch.object(b.Path, "is_file", return_value=True), \
             patch.object(b, "desktop_exec", return_value=""), \
             patch.object(b, "dpkg_owners", return_value={}):
            files, attributed, loose = b.attribute_desktops(index)
        self.assertEqual(attributed, {str(desktop): "firefox-spark"})
        self.assertEqual(loose, {str(desktop)})
        self.assertIn(Path("/opt/apps/firefox-spark/entries/applications/firefox-spark.desktop"), files)

    def test_ambiguous_basename_is_not_guessed(self):
        """两个包都叫同一个入口名时不能瞎认。"""
        desktop = Path("/usr/share/applications/dup.desktop")
        index = {"pkg-a": ["/opt/a/entries/applications/dup.desktop"],
                 "pkg-b": ["/opt/b/entries/applications/dup.desktop"]}
        with patch.object(b, "desktop_dirs", return_value=[Path("/usr/share/applications")]), \
             patch.object(b.Path, "is_dir", return_value=True), \
             patch.object(b.Path, "glob", return_value=[]), \
             patch.object(b.Path, "is_file", return_value=True), \
             patch.object(b, "desktop_exec", return_value=""), \
             patch.object(b, "dpkg_owners", return_value={}):
            _, attributed, _ = b.attribute_desktops(index)
        self.assertEqual(attributed, {})

    def test_unattributable_desktop_is_not_listed(self):
        """没有任何包接手时不该硬塞进列表：没有包就没有卸载计划。"""
        desktop = Path("/usr/share/applications/android-studio.desktop")
        with patch.object(b, "desktop_dirs", return_value=[Path("/usr/share/applications")]), \
             patch.object(b.Path, "is_dir", return_value=True), \
             patch.object(b.Path, "glob", return_value=[]), \
             patch.object(b.Path, "is_file", return_value=True), \
             patch.object(b, "desktop_exec", return_value="/opt/android-studio/bin/studio.sh"), \
             patch.object(b, "dpkg_owners", return_value={}):
            _, attributed, loose = b.attribute_desktops({})
        self.assertEqual(attributed, {})
        self.assertEqual(loose, set())

    def test_package_entries_ignores_component_internals(self):
        """只认 entries/applications/。gdm 的 greeter 目录里躺着 Exec=true 的
        内部 .desktop，照单全收就会多出一条用户根本没装过的"Dummy URI Handler"。"""
        index = {
            "com.douyin.otohime": ["/opt/apps/com.douyin.otohime/entries/applications/douyin.desktop"],
            "gdm3": ["/usr/share/gdm/greeter/applications/mime-dummy-handler.desktop"],
            "vlc": ["/usr/share/applications/vlc.desktop"],
        }
        found, by_name = b.package_entries(index)
        self.assertEqual([str(p) for p in found],
                         ["/opt/apps/com.douyin.otohime/entries/applications/douyin.desktop"])
        self.assertEqual(by_name, {"douyin.desktop": {"com.douyin.otohime"}})

    def test_desktop_exec_only_accepts_absolute_paths(self):
        """只有绝对路径能拿去反查包；env FOO=1 /path 这种包一层壳的也不认，
        否则归属的是 env 自己。"""
        with tempfile.TemporaryDirectory() as tmp:
            def write(name, exec_line):
                path = Path(tmp) / name
                path.write_text(f"[Desktop Entry]\nExec={exec_line}\n")
                return path
            self.assertEqual(b.desktop_exec(write("a", "/opt/app/bin/app %U")), "/opt/app/bin/app")
            self.assertEqual(b.desktop_exec(write("b", "app %U")), "")
            self.assertEqual(b.desktop_exec(write("c", "env FOO=1 /opt/app/bin/app")), "")
            self.assertEqual(b.desktop_exec(write("d", "")), "")


class MeasuredSizeTests(unittest.TestCase):
    """Installed-Size 不可信时实测 —— 不少应用把预编译目录塞进 /opt 却只申报一小部分。"""

    def test_sums_only_the_packages_own_files(self):
        """只累加包自己拥有的文件。测目录会把同目录下别的包一起算进来。"""
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a"
            a.mkdir()
            (a / "one").write_bytes(b"x" * 4096)
            (a / "two").write_bytes(b"x" * 4096)
            total = b.measured_size([str(a / "one"), str(a / "two"), str(a / "gone")])
        self.assertGreaterEqual(total, 8192)      # 两个 4K 文件
        self.assertLess(total, 8192 * 4)           # 第三个不存在，不应拖累

    def test_abstains_on_empty_or_enormous_file_lists(self):
        self.assertEqual(b.measured_size([]), 0)
        self.assertEqual(b.measured_size(["/x"] * 10, limit=5), 0)

    def test_only_bundles_outside_system_dirs_are_re_measured(self):
        """普通系统包的 Installed-Size 是准的，别白跑一遍 stat。"""
        self.assertFalse(b.needs_measurement(["/usr/bin/foo", "/usr/share/doc/foo/copyright"]))
        self.assertTrue(b.needs_measurement(["/opt/apps/foo/files/foo"]))


class LooseCleanupTests(unittest.TestCase):
    """卸载后清理游离 .desktop —— 四道闸门必须同时成立。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.menu = Path(self.tmp.name) / "applications"
        self.menu.mkdir()
        self.addCleanup(self.tmp.cleanup)

    def _unowned(self, paths):
        return {}

    def _owned(self, owned):
        return lambda paths: {str(p): "somepkg" for p in paths if str(p) in owned}

    def test_removes_unowned_desktop_inside_menu_dir(self):
        f = self.menu / "douyin.desktop"
        f.write_text("[Desktop Entry]\n")
        with patch.object(b, "dpkg_owners", side_effect=self._unowned):
            self.assertEqual([p.name for p in b.loose_targets([str(f)], [str(self.menu)])], ["douyin.desktop"])

    def test_never_touches_package_owned_file(self):
        """包拥有的文件必须留给 dpkg：手删会让 dpkg 认为文件还在。"""
        f = self.menu / "douyin.desktop"
        f.write_text("[Desktop Entry]\n")
        with patch.object(b, "dpkg_owners", side_effect=self._owned({str(f)})):
            self.assertEqual(b.loose_targets([str(f)], [str(self.menu)]), [])

    def test_rejects_paths_outside_the_menu_dir(self):
        outside = Path(self.tmp.name) / "evil.desktop"
        outside.write_text("[Desktop Entry]\n")
        with patch.object(b, "dpkg_owners", side_effect=self._unowned):
            self.assertEqual(b.loose_targets([str(outside)], [str(self.menu)]), [])

    def test_rejects_traversal_and_other_suffixes(self):
        escape = self.menu / ".." / "escape.desktop"
        escape.write_text("[Desktop Entry]\n")
        plain = self.menu / "notes.txt"
        plain.write_text("x")
        with patch.object(b, "dpkg_owners", side_effect=self._unowned):
            got = b.loose_targets([str(plain), str(escape) + "/../escape.desktop"],
                                  [str(self.menu)])
        self.assertEqual(got, [])

    def test_symlink_kept_unless_it_points_into_the_removed_package(self):
        """菜单里的软链指向包自带入口时该删（否则留个断链），
        指向别处的一律不动。"""
        target = Path(self.tmp.name) / "entries.desktop"
        target.write_text("[Desktop Entry]\n")
        alias = self.menu / "alias.desktop"
        alias.symlink_to(target)
        foreign = Path(self.tmp.name) / "foreign.desktop"
        foreign.write_text("[Desktop Entry]\n")
        other = self.menu / "other.desktop"
        other.symlink_to(foreign)
        owned = {str(target)}
        with patch.object(b, "dpkg_owners", side_effect=self._unowned), \
             patch.object(b, "dpkg_file_index", return_value={"pkg": [str(target)]}):
            self.assertEqual([p.name for p in b.loose_targets([str(alias)], [str(self.menu)], "pkg")],
                             ["alias.desktop"])
            self.assertEqual(b.loose_targets([str(other)], [str(self.menu)], "pkg"), [])
            # 不给包名时无从判断目标，一律保守地不删
            self.assertEqual(b.loose_targets([str(alias)], [str(self.menu)]), [])

    def test_survives_garbage_input(self):
        with patch.object(b, "dpkg_owners", side_effect=self._unowned):
            self.assertEqual(b.loose_targets(None, [str(self.menu)]), [])
            self.assertEqual(b.loose_targets([None, 42, "", "  "], [str(self.menu)]), [])


if __name__ == "__main__":
    unittest.main()
