# frozen_string_literal: true
# -*- encoding: utf-8 -*-
# stub: bundler 2.1.4 ruby lib

Gem::Specification.new do |s|
  s.name = "bundler".freeze
  s.version = "2.1.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 2.5.2".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/bundler/bundler/issues", "changelog_uri" => "https://github.com/bundler/bundler/blob/master/CHANGELOG.md", "homepage_uri" => "https://bundler.io/", "source_code_uri" => "https://github.com/bundler/bundler/" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Andr\u00E9 Arko".freeze, "Samuel Giddins".freeze, "Colby Swandale".freeze, "Hiroshi Shibata".freeze, "David Rodr\u00EDguez".freeze, "Grey Baker".freeze, "Stephanie Morillo".freeze, "Chris Morris".freeze, "James Wen".freeze, "Tim Moore".freeze, "Andr\u00E9 Medeiros".freeze, "Jessica Lynn Suttles".freeze, "Terence Lee".freeze, "Carl Lerche".freeze, "Yehuda Katz".freeze]
  s.bindir = "exe".freeze
  s.date = "2020-01-05"
  s.description = "Bundler manages an application's dependencies through its entire life, across many machines, systematically and repeatably".freeze
  s.email = ["team@bundler.io".freeze]
  s.executables = ["bundle".freeze, "bundler".freeze]
  s.files = ["exe/bundle".freeze, "exe/bundler".freeze]
  s.homepage = "https://bundler.io".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3.0".freeze)
  s.rubygems_version = "3.1.2".freeze
  s.summary = "The best way to manage your application's dependencies".freeze

  s.installed_by_version = "3.1.2" if s.respond_to? :installed_by_version
end