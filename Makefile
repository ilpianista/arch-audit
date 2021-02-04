-include Makefile.local

DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
DATAROOTDIR ?= ${PREFIX}/share
MANDIR ?= ${DATAROOTDIR}/man
SYSTEMDDIR ?= ${PREFIX}/lib/systemd/system

TARBALLDIR ?= target/release/tarball
TARBALLFORMAT=tar.gz

RM := rm
CARGO := cargo
SCDOC := scdoc
INSTALL := install
GIT := git
GPG := gpg
SED := sed

DEBUG := 0
ifeq ($(DEBUG), 0)
	CARGO_OPTIONS := --release --locked
	CARGO_TARGET := release
else
	CARGO_OPTIONS :=
	CARGO_TARGET := debug
endif

.PHONY: all arch-audit test docs man completions clean install uninstall

all: arch-audit test docs

arch-audit:
	$(CARGO) build $(CARGO_OPTIONS)

test:
	$(CARGO) test $(CARGO_OPTIONS)

lint:
	$(CARGO) fmt -- --check
	$(CARGO) check
	find . -name '*.rs' -exec touch {} +
	$(CARGO) clippy --all -- -D warnings

docs: man completions

man: contrib/man/arch-audit.1

contrib/man/%.1: contrib/man/%.scd
	$(SCDOC) < $^ > $@

completions: arch-audit
	target/$(CARGO_TARGET)/arch-audit completions bash | $(INSTALL) -Dm 644 /dev/stdin target/completion/bash/arch-audit
	target/$(CARGO_TARGET)/arch-audit completions zsh | $(INSTALL) -Dm 644 /dev/stdin target/completion/zsh/_arch-audit
	target/$(CARGO_TARGET)/arch-audit completions fish | $(INSTALL) -Dm 644 /dev/stdin target/completion/fish/arch-audit.fish

clean:
	$(RM) -rf target contrib/man/*.1

install: arch-audit docs
	$(INSTALL) -Dm 755 target/$(CARGO_TARGET)/arch-audit -t $(DESTDIR)$(BINDIR)
	$(INSTALL) -Dm 644 contrib/man/*.1 -t $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -Dm 644 target/completion/bash/arch-audit -t $(DESTDIR)$(DATAROOTDIR)/bash-completion/completions
	$(INSTALL) -Dm 644 target/completion/zsh/_arch-audit -t $(DESTDIR)$(DATAROOTDIR)/zsh/site-functions
	$(INSTALL) -Dm 644 target/completion/fish/arch-audit.fish -t $(DESTDIR)$(DATAROOTDIR)/fish/vendor_completions.d
	$(INSTALL) -Dm 644 contrib/systemd/arch-audit.* -t $(DESTDIR)$(SYSTEMDDIR)

uninstall:
	$(RM) -f $(DESTDIR)$(BINDIR)/arch-audit
	$(RM) -f $(DESTDIR)$(MANDIR)/man1/arch-audit.1
	$(RM) -f $(DESTDIR)$(DATAROOTDIR)/bash-completion/completions/arch-audit
	$(RM) -f $(DESTDIR)$(DATAROOTDIR)/zsh/site-functions/_arch-audit
	$(RM) -f $(DESTDIR)$(DATAROOTDIR)/fish/vendor_completions.d/arch-audit.fish

release: all
	$(INSTALL) -d $(TARBALLDIR)
	@read -p 'version> ' TAG && \
		$(SED) "s|version = .*|version = \"$$TAG\"|" -i Cargo.toml && \
		$(CARGO) build --release && \
		$(GIT) commit --gpg-sign --message "version: release $$TAG" Cargo.toml Cargo.lock && \
		$(GIT) tag --sign --message "version: release $$TAG" $$TAG && \
		$(GIT) archive -o $(TARBALLDIR)/arch-audit-$$TAG.$(TARBALLFORMAT) --format $(TARBALLFORMAT) --prefix=arch-audit-$$TAG/ $$TAG && \
		$(GPG) --detach-sign $(TARBALLDIR)/arch-audit-$$TAG.$(TARBALLFORMAT)
