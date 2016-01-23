#!/usr/bin/env ruby

ALL_FILES = Dir["**/*"]

def guess_path(filename, allfiles=ALL_FILES)
  return allfiles.find_all { |f| f.end_with?(filename) and File.basename(f) == File.basename(filename) }
end

def is_pointer_cast_line?(line, colstart)
  return (not line.nil? and line[colstart-1..-1] =~ /^\(.+?\)\s*.+$/) # check if there is a cast-like thing starting at colstart
end

class Debug
  def initialize()
    @addr_lines = {}
  end
  
  def addr2line(executable, addr)
    unique_addr = executable + ":" + addr
    if not @addr_lines.has_key?(unique_addr)
      s = `addr2line -e #{executable} #{addr}`
      f, l = s.split(":")
      @addr_lines[unique_addr] = [f, l.to_i]
    end
    return @addr_lines[unique_addr]
  end
end
