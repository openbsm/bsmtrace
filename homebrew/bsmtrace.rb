class Bsmtrace < Formula
  desc "BSM based intrusion detection system"
  homepage "http://www.trustedbsd.org/bsmtrace.html"
  url "https://github.com/openbsm/bsmtrace/archive/v2.0.2.tar.gz"
  sha256 "dfd5ba0aa9dcbdec7ee47db316b35696fe77032044dbe578fcc9c6b9c0cefdb8"

  depends_on "openssl"
  depends_on "pcre"

  def install
    system "make"
    system "make", "PREFIX=#{prefix}", "install"
  end

  test do
    system "#{bin}/bsmtrace", "-n", "-f", "#{prefix}/etc/bsmtrace.conf"
  end
end
