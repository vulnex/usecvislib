#
# VULNEX -Universal Security Visualization Library-
#
# File: test_binvis.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-23
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for binvis module."""

import os
import random
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from usecvislib.binvis import BinVis


class TestBinVisInit:
    """Tests for BinVis initialization."""

    def test_init_defaults(self):
        """Test default initialization values."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        assert bv.format == "png"
        assert bv.styleid == "bv_default"
        assert bv.inputfile == "input.bin"
        assert bv.outputfile == "output"

    def test_init_custom_format(self):
        """Test custom format initialization."""
        bv = BinVis("input.bin", "output", format="svg", validate_paths=False)
        assert bv.format == "svg"

    def test_init_custom_style(self):
        """Test custom style initialization."""
        bv = BinVis("input.bin", "output", styleid="bv_dark", validate_paths=False)
        assert bv.styleid == "bv_dark"


class TestBinVisLoad:
    """Tests for binary data loading."""

    def test_load_valid_file(self):
        """Test loading a valid binary file."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02\x03\x04\x05")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                data = bv.load()
                assert data == b"\x00\x01\x02\x03\x04\x05"
                assert bv.data == data
            finally:
                os.unlink(f.name)

    def test_load_missing_file(self):
        """Test loading a non-existent file."""
        bv = BinVis("/nonexistent/file.bin", "output", validate_paths=False)
        with pytest.raises(FileNotFoundError):
            bv.load()

    def test_load_empty_file(self):
        """An empty file is rejected (charts of nothing leaked Matplotlib warnings)."""
        from usecvislib.utils import ValidationError

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.flush()  # Empty file
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                with pytest.raises(ValidationError):
                    bv.load()
            finally:
                os.unlink(f.name)


class TestBinVisEntropy:
    """Tests for entropy calculations."""

    def test_calculate_entropy_uniform(self):
        """Test entropy of uniformly distributed data."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        # Create data with all possible byte values equally distributed
        data = bytes(range(256)) * 10
        entropy = bv.calculate_entropy(data)
        # Should be close to 8 (maximum entropy for bytes)
        assert 7.9 < entropy < 8.1

    def test_calculate_entropy_single_value(self):
        """Test entropy of constant data."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        data = b"\x00" * 1000
        entropy = bv.calculate_entropy(data)
        # Should be 0 (no randomness)
        assert entropy == 0.0

    def test_calculate_entropy_empty(self):
        """Test entropy of empty data."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        entropy = bv.calculate_entropy(b"")
        assert entropy == 0.0

    def test_sliding_entropy(self):
        """Test sliding window entropy calculation."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write some varied data
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                positions, entropies = bv.sliding_entropy(window_size=256, step=64)
                assert len(positions) > 0
                assert len(positions) == len(entropies)
                # All entropy values should be between 0 and 8
                assert all(0 <= e <= 8 for e in entropies)
            finally:
                os.unlink(f.name)


class TestBinVisDistribution:
    """Tests for byte distribution calculations."""

    def test_byte_distribution(self):
        """Test byte frequency distribution."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write known data
            f.write(b"\x00\x00\x01\x01\x01\xff")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                dist = bv.byte_distribution()
                assert len(dist) == 256
                assert dist[0] == pytest.approx(2 / 6)  # Two 0x00 bytes
                assert dist[1] == pytest.approx(3 / 6)  # Three 0x01 bytes
                assert dist[255] == pytest.approx(1 / 6)  # One 0xFF byte
            finally:
                os.unlink(f.name)


class TestBinVisStats:
    """Tests for file statistics."""

    def test_get_file_stats(self):
        """Test file statistics generation."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write mixed data
            f.write(b"Hello World!\x00\x00\x00")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                stats = bv.get_file_stats()
                assert stats["file_size"] == 15
                assert stats["unique_bytes"] > 0
                assert "entropy" in stats
                assert "null_percentage" in stats
                assert "printable_percentage" in stats
            finally:
                os.unlink(f.name)


class TestBinVisStreaming:
    """Tests for streaming binary analysis (Phase 3)."""

    def test_load_mmap(self):
        """Test memory-mapped file loading."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                mapped = bv.load_mmap()
                # Should be able to access data like a bytes object
                assert len(mapped) == 1024
                assert mapped[0] == 0
                assert mapped[255] == 255
                bv.close_mmap()
            finally:
                os.unlink(f.name)

    def test_close_mmap(self):
        """Test memory-mapped file cleanup."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                bv.load_mmap()
                bv.close_mmap()
                # After closing, _mmap and _file should be None
                assert bv._mmap is None
                assert bv._file is None
            finally:
                os.unlink(f.name)

    def test_load_chunked(self):
        """Test chunked file loading generator."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write 100 bytes
            f.write(bytes(range(100)))
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                # Use small chunk size for testing
                chunks = list(bv.load_chunked(chunk_size=25))
                assert len(chunks) == 4  # 100 / 25 = 4 chunks
                # Reassemble and verify
                reassembled = b"".join(chunks)
                assert reassembled == bytes(range(100))
            finally:
                os.unlink(f.name)

    def test_load_chunked_is_generator(self):
        """Test that load_chunked returns a generator."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00" * 100)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                gen = bv.load_chunked()
                # Should be a generator
                assert hasattr(gen, "__iter__")
                assert hasattr(gen, "__next__")
            finally:
                os.unlink(f.name)

    def test_calculate_entropy_streaming(self):
        """Test streaming entropy calculation."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Uniform data should have high entropy
            f.write(bytes(range(256)) * 10)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                entropy = bv.calculate_entropy_streaming()
                # Should be close to 8 (maximum for bytes)
                assert 7.9 < entropy < 8.1
            finally:
                os.unlink(f.name)

    def test_calculate_entropy_streaming_constant(self):
        """Test streaming entropy for constant data."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Constant data should have zero entropy
            f.write(b"\x00" * 1000)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                entropy = bv.calculate_entropy_streaming()
                assert entropy == 0.0
            finally:
                os.unlink(f.name)

    def test_sliding_entropy_streaming(self):
        """Test streaming sliding window entropy."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write enough data for sliding window
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                results = list(bv.sliding_entropy_streaming(window_size=256, step=64))
                # Should have multiple (position, entropy) tuples
                assert len(results) > 0
                for pos, entropy in results:
                    assert isinstance(pos, int)
                    assert pos >= 0
                    assert 0 <= entropy <= 8
            finally:
                os.unlink(f.name)

    def test_sliding_entropy_streaming_is_generator(self):
        """Test that sliding_entropy_streaming returns a generator."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                gen = bv.sliding_entropy_streaming()
                # Should be a generator
                assert hasattr(gen, "__iter__")
                assert hasattr(gen, "__next__")
            finally:
                os.unlink(f.name)

    def test_get_file_stats_streaming(self):
        """Test streaming file statistics."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Write mixed data
            f.write(b"Hello World!\x00\x00\x00")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                stats = bv.get_file_stats_streaming()
                assert stats["file_size"] == 15
                assert "entropy" in stats
                assert "unique_bytes" in stats
                assert "null_percentage" in stats
                assert "printable_percentage" in stats
            finally:
                os.unlink(f.name)

    def test_streaming_matches_regular(self):
        """Test that streaming entropy matches regular entropy."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            # Random-ish data
            import random

            random.seed(42)
            data = bytes([random.randint(0, 255) for _ in range(1000)])
            f.write(data)
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                bv.load()
                regular_entropy = bv.calculate_entropy(bv.data)
                streaming_entropy = bv.calculate_entropy_streaming()
                # Should be very close
                assert abs(regular_entropy - streaming_entropy) < 0.01
            finally:
                os.unlink(f.name)


class TestBinVisConfig:
    """Tests for binary visualization configuration (Phase 6)."""

    def test_default_config(self):
        """Test default configuration is loaded."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        assert "entropy_analysis" in bv.config
        assert "byte_distribution" in bv.config
        assert "wind_rose" in bv.config
        assert "heatmap" in bv.config

    def test_default_config_values(self):
        """Test default configuration values are correct."""
        bv = BinVis("input.bin", "output", validate_paths=False)
        # Entropy defaults
        assert bv.config["entropy_analysis"]["window_size"] == 256
        assert bv.config["entropy_analysis"]["step"] == 64
        assert bv.config["entropy_analysis"]["show_thresholds"] is True
        # Distribution defaults
        assert bv.config["byte_distribution"]["bar_width"] == 1.0
        assert bv.config["byte_distribution"]["show_regions"] is True
        # Wind rose defaults
        assert bv.config["wind_rose"]["bar_alpha"] == 0.7
        # Heatmap defaults
        assert bv.config["heatmap"]["block_size"] == 256
        assert bv.config["heatmap"]["interpolation"] == "nearest"

    def test_load_config_from_file(self):
        """Test loading configuration from a TOML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[entropy_analysis]
window_size = 512
step = 128

[heatmap]
block_size = 128
""")
            f.flush()
            try:
                bv = BinVis("input.bin", "output", configfile=f.name, validate_paths=False)
                # Custom values should be loaded
                assert bv.config["entropy_analysis"]["window_size"] == 512
                assert bv.config["entropy_analysis"]["step"] == 128
                assert bv.config["heatmap"]["block_size"] == 128
                # Default values should still exist
                assert bv.config["entropy_analysis"]["dpi"] == 150
                assert bv.config["byte_distribution"]["bar_width"] == 1.0
            finally:
                os.unlink(f.name)

    def test_config_merge_preserves_defaults(self):
        """Test that config merging preserves unspecified defaults."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[entropy_analysis]
window_size = 1024
""")
            f.flush()
            try:
                bv = BinVis("input.bin", "output", configfile=f.name, validate_paths=False)
                # Custom value applied
                assert bv.config["entropy_analysis"]["window_size"] == 1024
                # Other entropy defaults preserved
                assert bv.config["entropy_analysis"]["step"] == 64
                assert bv.config["entropy_analysis"]["fill_alpha"] == 0.3
                # Other sections still have defaults
                assert bv.config["heatmap"]["block_size"] == 256
            finally:
                os.unlink(f.name)

    def test_config_file_not_found_is_an_error(self):
        """An explicitly given config that is missing is an error, not silent defaults."""
        from usecvislib.utils import ConfigError

        with pytest.raises(ConfigError):
            BinVis("input.bin", "output", configfile="/nonexistent/config.toml", validate_paths=False)

    def test_invalid_config_is_an_error(self, tmp_path):
        from usecvislib.utils import ConfigError

        bad = tmp_path / "bad.toml"
        bad.write_text("[entropy_analysis\nwindow_size = ", encoding="utf-8")
        with pytest.raises(ConfigError):
            BinVis("input.bin", "output", configfile=str(bad), validate_paths=False)

    def test_loadconfig_with_custom_thresholds(self):
        """Test loading config with custom entropy thresholds."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[entropy_analysis]
show_thresholds = true

[[entropy_analysis.thresholds]]
value = 6.0
color = "orange"
style = "-"
alpha = 0.8
label = "Custom threshold"
""")
            f.flush()
            try:
                bv = BinVis("input.bin", "output", configfile=f.name, validate_paths=False)
                thresholds = bv.config["entropy_analysis"]["thresholds"]
                assert len(thresholds) == 1
                assert thresholds[0]["value"] == 6.0
                assert thresholds[0]["color"] == "orange"
            finally:
                os.unlink(f.name)

    def test_loadconfig_with_custom_regions(self):
        """Test loading config with custom distribution regions."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("""
[byte_distribution]
show_regions = true

[[byte_distribution.regions]]
start = 0
end = 127
color = "blue"
alpha = 0.2
label = "Lower half"

[[byte_distribution.regions]]
start = 128
end = 255
color = "red"
alpha = 0.2
label = "Upper half"
""")
            f.flush()
            try:
                bv = BinVis("input.bin", "output", configfile=f.name, validate_paths=False)
                regions = bv.config["byte_distribution"]["regions"]
                assert len(regions) == 2
                assert regions[0]["start"] == 0
                assert regions[0]["end"] == 127
                assert regions[1]["start"] == 128
            finally:
                os.unlink(f.name)

    def test_visualize_entropy_uses_config(self):
        """Test that visualize_entropy uses config values."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as binfile:
            binfile.write(bytes(range(256)) * 8)
            binfile.flush()
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as configfile:
                    configfile.write("""
[entropy_analysis]
window_size = 128
step = 32
dpi = 100
show_grid = false
show_thresholds = false
""")
                    configfile.flush()
                    try:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            output = os.path.join(tmpdir, "test")
                            bv = BinVis(binfile.name, output, format="png", configfile=configfile.name)
                            bv.load()
                            # Should use config values (window_size=128)
                            bv.visualize_entropy()
                            assert os.path.exists(f"{output}_entropy.png")
                    finally:
                        os.unlink(configfile.name)
            finally:
                os.unlink(binfile.name)

    def test_visualize_heatmap_uses_config_block_size(self):
        """Test that visualize_heatmap uses config block_size."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as binfile:
            binfile.write(bytes(range(256)) * 8)
            binfile.flush()
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as configfile:
                    configfile.write("""
[heatmap]
block_size = 64
show_colorbar = false
""")
                    configfile.flush()
                    try:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            output = os.path.join(tmpdir, "test")
                            bv = BinVis(binfile.name, output, format="png", configfile=configfile.name)
                            bv.load()
                            bv.visualize_heatmap()
                            assert os.path.exists(f"{output}_heatmap.png")
                    finally:
                        os.unlink(configfile.name)
            finally:
                os.unlink(binfile.name)

    def test_explicit_params_override_config(self):
        """Test that explicit method parameters override config values."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as binfile:
            binfile.write(bytes(range(256)) * 8)
            binfile.flush()
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as configfile:
                    configfile.write("""
[entropy_analysis]
window_size = 512
step = 128
""")
                    configfile.flush()
                    try:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            output = os.path.join(tmpdir, "test")
                            bv = BinVis(binfile.name, output, format="png", configfile=configfile.name)
                            bv.load()
                            # Config says 512/128, but we explicitly pass 256/64
                            bv.visualize_entropy(window_size=256, step=64)
                            assert os.path.exists(f"{output}_entropy.png")
                    finally:
                        os.unlink(configfile.name)
            finally:
                os.unlink(binfile.name)

    def test_init_with_configfile_param(self):
        """Test BinVis initialization with configfile parameter."""
        bv = BinVis("input.bin", "output", configfile="", validate_paths=False)
        assert bv.configfile == ""
        # Should still have defaults
        assert bv.config["entropy_analysis"]["window_size"] == 256


class TestBinVisVisualization:
    """Tests for visualization generation."""

    def test_visualize_entropy(self):
        """Test entropy visualization generation."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "test")
                    bv = BinVis(f.name, output, format="png")
                    bv.load()
                    bv.visualize_entropy()
                    assert os.path.exists(f"{output}_entropy.png")
            finally:
                os.unlink(f.name)

    def test_visualize_distribution(self):
        """Test distribution visualization generation."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "test")
                    bv = BinVis(f.name, output, format="png")
                    bv.load()
                    bv.visualize_distribution()
                    assert os.path.exists(f"{output}_distribution.png")
            finally:
                os.unlink(f.name)

    def test_build_binvis_all(self):
        """Test complete build process with all visualizations."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "test")
                    bv = BinVis(f.name, output, format="png")
                    bv.BuildBinVis("all")
                    # Check all output files exist
                    assert os.path.exists(f"{output}_entropy.png")
                    assert os.path.exists(f"{output}_distribution.png")
                    assert os.path.exists(f"{output}_windrose.png")
                    assert os.path.exists(f"{output}_heatmap.png")
                    assert os.path.exists(f"{output}_digraph.png")
            finally:
                os.unlink(f.name)

    def test_build_binvis_invalid_type(self):
        """Test build with invalid visualization type."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02")
            f.flush()
            try:
                bv = BinVis(f.name, "output", validate_paths=False)
                with pytest.raises(ValueError, match="Unknown visualization type"):
                    bv.BuildBinVis("invalid")
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestBinVisStyling:
    """Presets visibly change the charts, and charts stay readable."""

    @staticmethod
    def _sample(tmp_path):
        # Mostly null bytes plus varied content, like a typical binary: the
        # dominant 0x00 used to flatten the wind rose to a single spike.
        path = tmp_path / "sample.bin"
        path.write_bytes(b"\x00" * 6000 + bytes(range(256)) * 20 + random.Random(0).randbytes(4000))
        return str(path)

    def _render(self, tmp_path, style, chart):
        out = tmp_path / f"{style}_{chart}"
        bv = BinVis(self._sample(tmp_path), str(out), format="png", styleid=style, validate_paths=False)
        bv.BuildBinVis(chart)
        return tmp_path / f"{style}_{chart}_{chart}.png"

    def test_entropy_uses_preset_colormap(self, tmp_path):
        a = self._render(tmp_path, "bv_corporate", "entropy").read_bytes()
        b = self._render(tmp_path, "bv_forest", "entropy").read_bytes()
        assert a != b

    def test_dark_preset_has_dark_background(self, tmp_path):
        from PIL import Image

        for chart in ("entropy", "distribution", "windrose", "heatmap", "digraph"):
            img = Image.open(self._render(tmp_path, "bv_dark", chart)).convert("L")
            assert img.getpixel((2, 2)) < 80, chart

    def test_windrose_not_dominated_by_one_byte(self, tmp_path):
        from PIL import Image

        img = Image.open(self._render(tmp_path, "bv_minimal", "windrose")).convert("RGB")
        colors = img.getcolors(img.width * img.height)
        non_white = sum(count for count, rgb in colors if min(rgb) < 230)
        assert non_white / (img.width * img.height) > 0.05


class TestBytePairs:
    """Byte-pair counts (vectorised), the wind rose built on them, and the digraph."""

    @staticmethod
    def _binvis(tmp_path, data, **kwargs):
        path = tmp_path / "sample.bin"
        path.write_bytes(data)
        return BinVis(str(path), str(tmp_path / "out"), format="png", validate_paths=False, **kwargs)

    def test_pair_counts_match_naive_loop(self, tmp_path):
        from collections import Counter

        data = random.Random(1).randbytes(5000) + b"\x00" * 300
        counts = self._binvis(tmp_path, data).byte_pair_counts()
        naive = Counter(zip(data, data[1:]))
        assert counts.shape == (256, 256)
        assert counts.sum() == len(data) - 1
        assert all(counts[a, b] == n for (a, b), n in naive.items())

    def test_pair_counts_tiny_input(self, tmp_path):
        assert self._binvis(tmp_path, b"A").byte_pair_counts().sum() == 0

    def test_windrose_direction_is_first_byte_count(self, tmp_path):
        # Same data as the old per-pair loop: occurrences of each value as a first byte
        data = b"AAAB" * 10
        directions = self._binvis(tmp_path, data).byte_pair_counts().sum(axis=1)
        assert directions[ord("A")] == 30 and directions[ord("B")] == 9

    def test_digraph_text_concentrates_in_printable_square(self, tmp_path):
        text = b"The quick brown fox jumps over the lazy dog. " * 200
        counts = self._binvis(tmp_path, text).byte_pair_counts()
        assert counts[0x20:0x7F, 0x20:0x7F].sum() == counts.sum()

    def test_digraph_renders_every_format(self, tmp_path):
        for fmt in ("png", "svg", "pdf"):
            bv = self._binvis(tmp_path, random.Random(2).randbytes(4096))
            bv.format = fmt
            bv.BuildBinVis("digraph")
            assert (tmp_path / f"out_digraph.{fmt}").stat().st_size > 0

    def test_visualize_all_includes_digraph(self, tmp_path):
        outputs = self._binvis(tmp_path, bytes(range(256)) * 4).visualize_all()
        assert [os.path.basename(o) for o in outputs] == [
            "out_entropy.png",
            "out_distribution.png",
            "out_windrose.png",
            "out_heatmap.png",
            "out_digraph.png",
        ]


class TestChartTitles:
    """display_name: the file name by default, a chosen name, or none."""

    def test_default_uses_file_name(self, tmp_path):
        bv = TestBytePairs._binvis(tmp_path, b"abc")
        assert bv._title("Binary Heatmap") == "Binary Heatmap: sample.bin"

    def test_custom_and_empty_names(self, tmp_path):
        assert TestBytePairs._binvis(tmp_path, b"abc", display_name="fw.img")._title("X") == "X: fw.img"
        assert TestBytePairs._binvis(tmp_path, b"abc", display_name="")._title("X") == "X"


class TestVectorisedStatistics:
    """The NumPy entropy and distribution match the previous per-byte loops."""

    def test_sliding_entropy_matches_counter_version(self, tmp_path):
        from collections import Counter

        import numpy as np
        from scipy.stats import entropy as scipy_entropy

        data = random.Random(3).randbytes(20000) + b"\x00" * 3000 + bytes(range(256)) * 10
        bv = TestBytePairs._binvis(tmp_path, data)
        for window, step in ((256, 64), (1000, 333), (64, 64)):
            positions, values = bv.sliding_entropy(window, step)
            expected_pos = list(range(0, len(data) - window + 1, step))
            expected = [scipy_entropy(list(Counter(data[i : i + window]).values()), base=2) for i in expected_pos]
            assert positions.tolist() == expected_pos
            assert np.allclose(values, expected)

    def test_sliding_entropy_short_input(self, tmp_path):
        positions, values = TestBytePairs._binvis(tmp_path, b"abc").sliding_entropy(256, 64)
        assert len(positions) == 0 and len(values) == 0

    def test_distribution_and_entropy_match_counter_version(self, tmp_path):
        from collections import Counter

        import numpy as np
        from scipy.stats import entropy as scipy_entropy

        data = random.Random(4).randbytes(9000) + b"A" * 1000
        bv = TestBytePairs._binvis(tmp_path, data)
        counts = Counter(data)
        expected = np.array([counts.get(v, 0) for v in range(256)]) / len(data)
        assert np.allclose(bv.byte_distribution(), expected)
        assert np.isclose(bv.calculate_entropy(data), scipy_entropy(list(counts.values()), base=2))


def test_matplotlib_backend_is_agg():
    # The API renders charts on worker threads; macOS's default GUI backend
    # refuses to create figures there (every binary chart returned 500).
    # Linux already defaults to Agg, so only this check catches a regression.
    import matplotlib

    import usecvislib.binvis  # noqa: F401  (selects the backend on import)

    assert matplotlib.get_backend().lower() == "agg"
