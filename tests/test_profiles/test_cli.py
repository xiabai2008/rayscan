import pytest
from wvs.cli import build_parser


def test_profile_list_command():
    parser = build_parser()
    args = parser.parse_args(["profile", "list"])
    assert args.profile_action == "list"
    assert args.format == "table"


def test_profile_list_json_format():
    parser = build_parser()
    args = parser.parse_args(["profile", "list", "--format", "json"])
    assert args.profile_action == "list"
    assert args.format == "json"


def test_profile_create_command():
    parser = build_parser()
    args = parser.parse_args([
        "profile", "create", "test-profile",
        "--modules", "sqli,xss",
        "--rate", "15",
        "--description", "Test profile",
    ])
    assert args.profile_action == "create"
    assert args.name == "test-profile"
    assert args.modules == "sqli,xss"
    assert args.rate == 15
    assert args.description == "Test profile"


def test_profile_delete_command():
    parser = build_parser()
    args = parser.parse_args(["profile", "delete", "my-profile", "--force"])
    assert args.profile_action == "delete"
    assert args.name == "my-profile"
    assert args.force is True


def test_profile_export_command():
    parser = build_parser()
    args = parser.parse_args(["profile", "export", "src-quick", "-o", "./my-profiles/"])
    assert args.profile_action == "export"
    assert args.name == "src-quick"
    assert args.output == "./my-profiles/"


def test_profile_import_command():
    parser = build_parser()
    args = parser.parse_args(["profile", "import", "./my-profiles/"])
    assert args.profile_action == "import"
    assert args.path == "./my-profiles/"


def test_use_command_basic():
    parser = build_parser()
    args = parser.parse_args([
        "use", "src-quick",
        "-u", "https://example.com",
    ])
    assert args.command == "use"
    assert args.profile == "src-quick"
    assert args.url == "https://example.com"


def test_use_command_full():
    parser = build_parser()
    args = parser.parse_args([
        "use", "pentest-full",
        "-u", "https://target.com",
        "-o", "report.json",
        "-f", "html",
        "-v",
        "--auth", "auth.json",
        "--max-time", "3600",
        "--insecure",
        "--modules", "sqli", "xss",
        "--no-modules", "cmdi",
    ])
    assert args.profile == "pentest-full"
    assert args.url == "https://target.com"
    assert args.output == "report.json"
    assert args.format == "html"
    assert args.verbose is True
    assert args.auth == "auth.json"
    assert args.max_time == 3600
    assert args.insecure is True
    assert args.modules == ["sqli", "xss"]
    assert args.disabled_modules == ["cmdi"]


def test_use_command_nonexistent_profile():
    parser = build_parser()
    args = parser.parse_args([
        "use", "nonexistent-profile",
        "-u", "https://example.com",
    ])
    # Profile validation happens at runtime, not at parse time
    assert args.profile == "nonexistent-profile"
