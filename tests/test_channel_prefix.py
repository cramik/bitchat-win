from bitchat import channel_prefix


def test_encode_with_no_channel_returns_content_unchanged():
    assert channel_prefix.encode("hello world", None) == "hello world"


def test_encode_with_a_channel_prepends_the_visible_prefix():
    assert channel_prefix.encode("hello world", "#general") == "#general: hello world"


def test_decode_round_trips_a_channel_tagged_message():
    wire = channel_prefix.encode("hello world", "#general")
    channel, content = channel_prefix.decode(wire)
    assert channel == "#general"
    assert content == "hello world"


def test_decode_of_plain_text_with_no_prefix_returns_none_channel():
    channel, content = channel_prefix.decode("just a normal message")
    assert channel is None
    assert content == "just a normal message"


def test_decode_preserves_multiline_content_after_the_prefix():
    channel, content = channel_prefix.decode("#dev: line one\nline two")
    assert channel == "#dev"
    assert content == "line one\nline two"


def test_decode_does_not_match_a_bare_hashtag_with_no_colon():
    channel, content = channel_prefix.decode("#justahashtag no colon here")
    assert channel is None
    assert content == "#justahashtag no colon here"


def test_decode_is_fooled_by_ordinary_text_matching_the_pattern():
    """Documents the real ambiguity: a message that was never meant to tag a
    channel, but happens to look like "#word: rest", gets misread as one.
    No dedicated wire field exists to disambiguate -- see channel_prefix.py's
    module docstring."""
    channel, content = channel_prefix.decode("#not-a-channel: this was just a sentence")
    assert channel == "#not-a-channel"
    assert content == "this was just a sentence"
