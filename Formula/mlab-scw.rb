class MlabScw < Formula
  desc "CLI over the Scaleway API, for read-only cloud posture audits"
  homepage "https://github.com/mlab-sh/mlab-scw"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-scw/releases/download/v#{version}/mlab-scw-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "d89e39362aab5af53f106bcfb697647a9327d34231eae2f21938c232c313f270"
    else
      url "https://github.com/mlab-sh/mlab-scw/releases/download/v#{version}/mlab-scw-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "bb70e2da4b9d8d6cee253758b4a50bbd8cb67eba0d9663c1876a2afb708c86a6"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-scw/releases/download/v#{version}/mlab-scw-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "fa3bcf5c9809e94078c76e8f06f1864be1173866efaf9ac9ead6905b16c51a1b"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-scw/releases/download/v#{version}/mlab-scw-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "cd9c32e3fbf53e41f339fbb47ea7c234543edde7589049ac91d4291e2819fa1e"
    end
  end

  def install
    bin.install "mlab-scw"
  end

  test do
    assert_match "mlab-scw", shell_output("#{bin}/mlab-scw --version")
  end
end
