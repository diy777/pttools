"""Tests for YAML plugin loader."""

import yaml

from tools.plugin_loader import load_plugins, validate_plugin


class TestLoadPlugins:
    def test_empty_dir(self, tmp_path):
        assert load_plugins(tmp_path) == []

    def test_nonexistent_dir(self, tmp_path):
        assert load_plugins(tmp_path / "nope") == []

    def test_loads_valid_plugin(self, tmp_path):
        plugin_yaml = {
            "name": "custom-scan",
            "category": "web",
            "command": "/usr/bin/custom-scan",
            "args": ["-t", "{target}"],
            "description": "Custom web scanner",
        }
        (tmp_path / "custom.yaml").write_text(yaml.dump(plugin_yaml))

        plugins = load_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0]["name"] == "custom-scan"
        assert plugins[0]["category"] == "web"
        assert plugins[0]["source"] == "plugin"

    def test_skips_invalid_plugin(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(yaml.dump({"name": "only-name"}))
        plugins = load_plugins(tmp_path)
        assert len(plugins) == 0

    def test_multiple_plugins_sorted(self, tmp_path):
        for i in range(3):
            data = {"name": f"tool-{i}", "category": "test", "command": f"/usr/bin/tool-{i}"}
            (tmp_path / f"tool-{i}.yaml").write_text(yaml.dump(data))

        plugins = load_plugins(tmp_path)
        assert len(plugins) == 3

    def test_malformed_yaml_skipped(self, tmp_path):
        (tmp_path / "bad.yaml").write_text("{{{{invalid yaml")
        plugins = load_plugins(tmp_path)
        assert len(plugins) == 0

    def test_default_fields(self, tmp_path):
        data = {"name": "minimal", "category": "test", "command": "scan"}
        (tmp_path / "min.yaml").write_text(yaml.dump(data))

        plugins = load_plugins(tmp_path)
        assert plugins[0]["output_parser"] == "raw"
        assert "which scan" in plugins[0]["install_check"]


class TestValidatePlugin:
    def test_valid_plugin(self):
        errors = validate_plugin({"name": "test", "command": "scan", "category": "web"})
        assert errors == []

    def test_missing_name(self):
        errors = validate_plugin({"command": "scan", "category": "web"})
        assert any("name" in e for e in errors)

    def test_missing_command(self):
        errors = validate_plugin({"name": "test", "category": "web"})
        assert any("command" in e for e in errors)
