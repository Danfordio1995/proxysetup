Name:           proxy_project
Version:        0.1.0
Release:        1%{?dist}
Summary:        High-Performance Proxy Server with Web Interface

License:        YourLicense
URL:            http://your-website.example.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust cargo
Requires:       systemd

%description
This is a high-performance proxy server with integrated TLS, ACL, advanced caching, 
rate limiting, and a secure web interface for monitoring and configuration.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release

%install
mkdir -p %{buildroot}/opt/proxy_project
install -m 0755 target/release/proxy_project %{buildroot}/opt/proxy_project/proxy_project

# Install the systemd service file.
install -Dm0644 proxy_project.service %{buildroot}/etc/systemd/system/proxy_project.service

%files
/opt/proxy_project/proxy_project
/etc/systemd/system/proxy_project.service

%changelog
* Tue Feb 18 2025 Your Name <you@example.com> - 0.1.0-1
- Initial RPM packaging. 