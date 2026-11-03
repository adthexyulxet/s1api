import pytest

from s1triage.config import ConfigError, Settings, load_dotenv


def test_requires_url_and_token():
    with pytest.raises(ConfigError):
        Settings.from_env({})
    with pytest.raises(ConfigError):
        Settings.from_env({"S1_API_URL": "https://x.sentinelone.net/web/api/v2.1"})


def test_parses_values_and_masks_token():
    s = Settings.from_env({
        "S1_API_URL": "https://x.sentinelone.net/web/api/v2.1/",
        "S1_API_TOKEN": "secret-value",
        "S1_POLL_INTERVAL": "10",
    })
    assert s.api_url.endswith("/v2.1")
    assert s.poll_interval == 10
    assert "secret-value" not in repr(s)


def test_rejects_bad_template():
    with pytest.raises(ConfigError):
        Settings.from_env({"S1_API_URL": "https://x", "S1_API_TOKEN": "t", "S1_DV_QUERY_TEMPLATE": "storyline = 1"})


def test_load_dotenv_does_not_override(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# c\nS1_API_TOKEN="abc"\nexport S1_API_URL=https://y\nEXISTING=new\n')
    env = {"EXISTING": "old"}
    load_dotenv(f, env)
    assert env == {"EXISTING": "old", "S1_API_TOKEN": "abc", "S1_API_URL": "https://y"}
