Name:           ctl365
Version:        0.1.0
Release:        1%{?dist}
Summary:        Enterprise-grade Microsoft 365 deployment automation CLI

License:        Proprietary
URL:            https://github.com/resotech/ctl365
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.85
BuildRequires:  cargo

%description
ctl365 is a command-line tool for automating Microsoft 365 deployments,
including security baselines, Conditional Access policies, Autopilot
configurations, and more.

%prep
%autosetup

%build
cargo build --release --locked

%install
install -Dm755 target/release/ctl365 %{buildroot}%{_bindir}/ctl365
install -Dm644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dm644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -Dm644 COMMANDS.md %{buildroot}%{_docdir}/%{name}/COMMANDS.md

%files
%license LICENSE
%doc README.md COMMANDS.md
%{_bindir}/ctl365

%changelog
* Mon Dec 09 2024 Christopher Kelley <christopher@resolvetech.biz> - 0.1.0-1
- Initial package
