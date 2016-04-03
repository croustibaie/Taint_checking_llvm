#!/usr/bin/env ruby

require "fileutils"

srcbase = "../instr_bop/bitnot"
destbase = ARGV[0]
destop = ARGV[1]

2.times { |i|
  src = "#{srcbase}0#{i+1}."
  dest = "#{destbase}0#{i+1}."

  FileUtils.cp(src+"c", dest+"c")
  [0, 1, 3].each { |n|
    FileUtils.cp(src+"O#{n}.output", dest+"O#{n}.output")
  }
  File.open(dest+"c", "w") { |f|
    f.write(File.read(src+"c").gsub("~", destop))
  }
}
