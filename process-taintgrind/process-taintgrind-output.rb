#!/usr/bin/env ruby

require "set"
require "colored.rb"
require "pathname"
require_relative "util.rb"

$idxwidth = 8
$verbose = false
$color = true

class TaintGrindOp
  @@debug = Debug.new
  
  def self.is_taintgrindop_line?(line)
    return line.split(" | ").length == 5
  end
  
  def initialize(line, idx)
    @idx = idx
    @line = line
    @is_sink = false
  
    elems = line.split(" | ")
    if elems[0] =~ /(0x\w+): (.+?) \((.+):(\d+)\)/  # e.g. 0x40080D: main (two-taints.c:10)
      @addr = $1
      @func = $2
      @file = $3
      @lineno = $4.to_i
    elsif elems[0] =~ /(0x\w+): (.+?) \(in (.+)\)/  # e.g. 0x40080D: main (in /tmp/a.out)
      @addr = $1
      @func = $2
      @file = $3
      @lineno = nil
    end

    preds = elems[4].split("; ")
    @from = []
    @var = nil
    
    preds.each do |pred|
      if pred =~ /^(.+?) <- (.+?)$/ # e.g. t54_1741 <- t42_1773, t29_4179
        self.set_var($1)
        @from += $2.split(", ")
      elsif pred =~ /^(.+?) <\*- (.+?)$/ # e.g. t78_744 <*- t72_268
#        self.set_var($1)
#        @from += $2.split(", ")
      #@is_sink = true
      elsif pred =~ /^(.+?) <-\*- (.+?)$/ # e.g. t78_744 <-*- t72_268
        # do nothing? like above
      else  # e.g. t54_1741
        @var = pred
      end
    end
    
    # is this a sink?
    # TODO this is just a basic approximation
    if elems[1].start_with?("IF ") or elems[1] =~ / = Add32/
      @is_sink = true
    end
    
    @preds = []
    @successor = nil
  end

  def set_var(var)
    if @var.nil?
      @var = var
    elsif @var != var
      raise RuntimeError.new("two different var values: #{@var} != #{var}")
    end
  end

  def get_lineno
    if @lineno.nil?
      @file, @lineno = @@debug.addr2line(@file, @addr)
    end
    return @lineno
  end

  def get_file
    if @lineno.nil?
      @file, @lineno = @@debug.addr2line(@file, @addr)
    end
    if not File.file?(@file)
      poss_files = guess_path(@file)
      poss_files.map! { |f| File.read(f).split("\n")[self.get_lineno-1].nil? ? nil : f }
      poss_file = poss_files.find { |f| not f.nil? }
      @file = File.expand_path(poss_file) if not poss_file.nil?
    end
    return @file
  end
  
  def is_source?
    return @preds.empty?
  end
  
  def is_tmp_var?
    return @var =~ /^t\d+_\d+$/
  end
  
  def is_use?
    return @from.empty?
  end
  
  def is_def?
    return (not self.is_use?)
  end
  
  def get_src_line
    begin
      return File.read(self.get_file).split("\n")[self.get_lineno-1].strip
    rescue
      return nil
    end
  end

  def to_s
    line = self.get_src_line
    line = "[file not found]" if line.nil?
    line = line.red if self.is_sink and $color

    file = Pathname.new(self.get_file)
    file = file.relative_path_from(Pathname.new(File.expand_path("."))) if file.absolute?
    
    return "%30s:%.4d: %20s:  %s" % [file.to_s, self.get_lineno, @func, line]
  end
  
  def get_sources
    # we can't use recursion here because the graph can be VERY huge and the
    # stack depth is just not enough for that
    sources = []
    stack = [self]
    visited = Set.new
    
    while not stack.empty?
      print "%20s  " % stack.map{|n|n.idx}.inspect if $verbose
      op = stack.pop
      
      if visited.include? op
        puts "already visited #{op.idx}, skipping" if $verbose
        next
      end
      visited.add op

      if $verbose
        w = 3
        print "detecting %#{$idxwidth}d" % op.idx
        print(op.successor.nil? ? " "*(6+$idxwidth) : (" from %#{$idxwidth}d" % op.successor.idx))
        print "  --  "
      end
      
      if op.is_source?
        puts "found source" if $verbose
        sources.push((not block_given? or yield op) ? op : op.successor)
      else
        puts "adding preds #{op.preds.map{|p|p.idx}.inspect}" if $verbose
        successor = (op.successor.nil? or not block_given? or yield op) ? op : op.successor
        op.preds.each do |p|
          if p.successor.nil? # if this one already has a successor the other one will be shorter
            p.successor = successor  # link from where we found this one
            stack.push p
          end
        end
      end
    end
    
    return sources
  end
  
  @@sources_no_tmp = lambda { |op| ((not op.is_tmp_var?) or op.is_sink) and (not block_given? or yield op) }
  @@sources_no_lib = lambda { |op| not op.get_src_line.nil? }
  
  def self.sources_no_tmp
    return @@sources_no_tmp
  end
  
  def self.sources_no_lib
    return @@sources_no_lib
  end
  
  def self.new_sources_unique_traces
    locs = Set.new
    return lambda { |op|
      loc = [op.get_file, op.get_lineno]
      incl = locs.include?(loc)
      locs.add(loc) if not incl
      not incl
    }
  end
  
  def get_trace_to_sink
    trace = []
    cur = self
    
    while not cur.nil?
      trace.push cur
      cur = cur.successor
    end
    
    return trace
  end
  
  attr_reader :func, :var, :from, :preds, :is_sink, :line, :idx
  attr_accessor :successor
end

###### PROCESS CLI ARGS ##########

HELPTEXT = <<HELP
Usage: process-taintgrind-output.rb [flags] <TAINTGRIND OUTPUT LOG>
The taintgrind output can also be piped into stdin.

This finds traces in the taintgrind output that lead to dangerous behavior.
Dangerous behavior is the dereferencing tainted values or their usage in
conditions. Tainted values are values derived from casts from pointers to
integrals.

Flags:
 -v, --verbose        Verbose mode
 -libs=yes|no         In the traces, show lines that are located in 3rd-party-
                      libraries. Specifically, a line is considered to be in a
                      library, if the source file cannot be found below the
                      current working directory. Default is no.
 -tmp-instr=yes|no    In the traces, show lines that affect only temporary
                      variables inserted by valgrind. Default is no.
 -unique-locs=yes|no  In the traces, don't show the same source location twice
                      (e.g. in a loop). This makes the trace incomplete but
                      avoids very big traces. Default is no.
 -src-only            Show only the sources, not the full trace.
 -taintgrind-trace    Show the taintgrind trace for the identified sinks.
 -mark-trace          For each trace print the whole taintgrind log but mark
                      the trace using color
 -no-color            Do not use terminal colors
HELP

taintgrind_trace = false
mark_trace = false
nolib = true
notmp = true
unique_locs = false
src_only = false

loop do
  case ARGV[0]
  when "-h", "--help", "-help"
    puts HELPTEXT
    exit
  when "-v", "--verbose"
    $verbose = true
    ARGV.shift
  when /^-libs=(yes|no)$/
    nolib = $1 == "no"
    ARGV.shift
  when /^-tmp-instr=(yes|no)$/
    notmp = $1 == "no"
    ARGV.shift
  when /^-unique-locs=(yes|no)$/
    unique_locs = $1 == "yes"
    ARGV.shift
  when "-src-only"
    src_only = true
    ARGV.shift
  when "-taintgrind-trace"
    taintgrind_trace = true
    ARGV.shift
  when "-mark-trace"
    mark_trace = true
    ARGV.shift
  when "-no-color"
    $color = false
    ARGV.shift
  when /^-/
    puts "Unrecognized argument #{ARGV[0]}"
    exit
  else
    break
  end
end

###### CREATE TaintGrindOp GRAPH ##########

# var -> TaintGrindOp
taintgrind_ops = {}
sinks = []

input_lines = ARGF.read.split("\n")
$idxwidth = input_lines.length.to_s.length

input_lines.each_with_index do |line, idx|
  if not TaintGrindOp.is_taintgrindop_line? line
    next
  end
  
  tgo = TaintGrindOp.new(line, idx)
  
  # link to predecessors
  tgo.from.each do |fromvar|
    if taintgrind_ops.has_key?(fromvar)
      tgo.preds.push(taintgrind_ops[fromvar])
    end
  end
  if tgo.is_use? and taintgrind_ops.has_key? tgo.var
    tgo.preds.push taintgrind_ops[tgo.var]
  end
  
  if tgo.is_def?
    if taintgrind_ops.has_key?(tgo.var)
      puts "ERROR: Duplicated definition"
    end
    taintgrind_ops[tgo.var] = tgo
  end
  
  if tgo.is_sink
    sinks.push tgo
  end
end

###### SHOW TRACES ##########

sinks.each do |sink|
  unique_traces_proc = TaintGrindOp.new_sources_unique_traces
  sources = sink.get_sources { |op| (not unique_locs or unique_traces_proc.call(op)) and
    (not notmp or TaintGrindOp.sources_no_tmp.call(op)) and
    (not nolib or TaintGrindOp.sources_no_lib.call(op)) }
  
  sources.each do |src|
    puts ">>>> The origin of the taint should be just here <<<<"
    if src_only
      puts src
    else
      trace = src.get_trace_to_sink

      if mark_trace
        output = input_lines.clone
        trace.each do |n|
          output[n.idx] = [n.is_sink, output[n.idx]]
        end
        output.each_with_index do |l,idx|
          print "%8d   " % idx

          if l.is_a? Array
            if $color
              puts(l[0] ? l[1].red : l[1].blue)
            else
              print(l[0] ? "[S]  " : "[T]  ")
              puts l[1]
            end
          else
            print "     " if not $color
            puts l
          end
        end
      else
        trace.map! { |n| n.line } if taintgrind_trace
        puts trace
      end
    end
    sep = "=" * 80
    puts($color ? sep.yellow : sep)
  end
end
