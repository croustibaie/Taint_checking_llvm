#!/usr/bin/env ruby
# coding: utf-8

require "set"
require "colored.rb"
require "pathname"
require_relative "util.rb"

$idxwidth = 8
$verbose = false
$color = true

class TaintGrindOp
  @@debug = Debug.new
  @@sink_lines = []

  def self.sink_lines()
    return @@sink_lines
  end
  
  def self.is_taintgrindop_line?(line)
    return line.split(" | ").length == 5
  end
  
  def initialize(line, idx, graph)
    @idx = idx
    @line = line

    loc, cmd, val, tnt, tnt_flow = line.split(" | ")
    if loc =~ /(0x\w+): (.+?) \((.+):(\d+)\)/  # e.g. 0x40080D: main (two-taints.c:10)
      @addr = $1
      @func = $2
      @file = $3
      @lineno = $4.to_i
    elsif loc =~ /(0x\w+): (.+?) \(in (.+)\)/  # e.g. 0x40080D: main (in /tmp/a.out)
      @addr = $1
      @func = $2
      @file = $3
      @lineno = nil
    end

    # parse taint information and flow and set predecessors
    @preds = []
    @var = nil
    @sink_reasons = []
    
    tnt_flow.split("; ").each do |pred|
      if pred =~ /^(.+?) <- (.+?)$/ # e.g. t54_1741 <- t42_1773, t29_4179
        self.set_var($1)
        @preds += $2.split(", ").map { |f| graph.has_key?(f) ? graph[f] : nil }
      elsif pred =~ /^(.+?) <\*- (.+?)$/ # e.g. t78_744 <*- t72_268
        # we MUST not dereference a red value, however this does not count as taintflow
        @sink_reasons += $2.split(", ").find_all {|f| graph.has_key?(f) and graph[f].is_red? }.map { |f| graph[f] }
      elsif pred =~ /^(.+?) <-\*- (.+?)$/ # e.g. t78_744 <-*- t72_268
        # we MUST not store at a red value
        @sink_reasons += $2.split(", ").find_all {|f| graph.has_key?(f) and graph[f].is_red? }.map { |f| graph[f] }
      else  # e.g. t54_1741
        @preds += pred.split(", ").map { |f| graph.has_key?(f) ? graph[f] : nil }
      end
    end

    self.inherit_taint()
    
    if not self.is_red?
      # is this an instruction that automatically leads to red taint
      if ((cmd =~ / = Add/ and @preds.length > 1) or
          (cmd =~ / = Sub\d\d? .+ (.+)/ and (@preds.length > 1 or (@preds.length == 1 and $1 == @preds[0].var))) or
          (cmd =~ / = Mul/) or
          (cmd =~ / = Div/) or
          (cmd =~ / = Mod/) or
          (cmd =~ / = And/) or
          (cmd =~ / = Or/) or
          (cmd =~ / = Xor/) or
          (cmd =~ / = Shl/) or
          (cmd =~ / = Sar/))
        @taint = :red
      elsif (cmd =~ / = Cmp/ and self.is_blue?) # at least one pred is blue then
        if @preds.find_all{|p|not p.nil? and p.is_blue?}.length > 1
          @taint = :green
        else # we know that at exactly one pred is blue because self.is_blue? above
          @taint = :red
        end
      end
    end
    
    # is this a sink?
    # cmp operations untaint the value -> we have to mark them as sink
    #@is_sink = (self.is_red? and (cmd =~ / = Cmp/))

    # remember: LOAD/STORE is already handled above
    if ((cmd =~ /^IF ([\w_]+) /) or
        (cmd =~ /[\w_]+ = ([\w_]+) \? [\w_]+ : [\w_]+/))
      # we can safely allow blue taint to reach a condition because
      # it is either 0 (null) in all variants or a valid pointer (-> true)
      @sink_reasons += @preds.find_all { |p| not p.nil? and p.is_red? and p.var == $1 }
    elsif (@func == "_Exit")
      # we must not allow returning tainted exit values
      @sink_reasons += @preds.find_all { |p| not p.nil? }
    end

    if not @@sink_lines.empty?
      if @@sink_lines.include?(idx+1)
        @sink_reasons += @preds if @sink_reasons.empty? # definitly add some reasons
      else
        @sink_reasons = [] # only marked sinks
      end
    end
  end

  def inherit_taint()
    @taint = self.is_source? ? :blue : :green

    @preds.each do |p|
      next if p.nil?
      if p.is_red?
        @taint = :red
        break # no return from here
      elsif p.is_blue?
        @taint = :blue
      end
    end
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
    return ((@preds+@sink_reasons).find{|p|not p.nil?}.nil?)
  end

  def is_sink?
    return (not @sink_reasons.empty?)
  end
  
  def is_tmp_var?
    return @var =~ /^t\d+_\d+$/
  end
  
  def is_use?
    return (not @preds.empty?)
  end
  
  def is_def?
    return (not @var.nil?)
  end

  def is_red?
    return @taint == :red
  end

  def is_blue?
    return @taint == :blue
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
    if $color
      if self.is_sink?
        line = line.magenta
      else
        line = case @taint
               when :red then line.red
               when :blue then line.blue
               when :green then line.green
               end
      end
      taint = ""
    end

    taint = case @taint
            when :red then "R"
            when :blue then "B"
            when :green then "G"
            else " "
            end
    
    file = Pathname.new(self.get_file)
    file = file.relative_path_from(Pathname.new(File.expand_path("."))) if file.absolute?
    
    return "%s%30s:%.4d: %20s:  %s" % [taint, file.to_s, self.get_lineno, @func, line]
  end
  
  def get_traces
    # we can't use recursion here because the graph can be VERY huge and the
    # stack depth is just not enough for that
    sources = []

    # all nodes that still need to be processed
    queue = [self]

    # a map from detected nodes to their successors
    detected = { self => nil }
    
    while not queue.empty?
      print "%30s  " % queue.map{|n|n.idx+1}.inspect if $verbose
      op = queue.shift

      
      if $verbose
        w = 3
        print "detecting %#{$idxwidth}d" % (op.idx+1)
        successor = detected[op]
        print(successor.nil? ? " "*(6+$idxwidth) : (" from %#{$idxwidth}d" % (successor.idx+1)))
        print "  --  "
      end
      
      if op.is_source?
        puts "found source" if $verbose
        sources.push((not block_given? or yield op) ? op : detected[op])
      else
        successor = (detected[op].nil? or not block_given? or yield op) ? op : detected[op]

        all_preds = op.is_sink? ? op.sink_reasons : op.preds
        
        # if this one was already detected the other path will be shorter
        preds = all_preds.find_all { |p| not p.nil? and not detected.has_key?(p) }
        
        # put the red ones first
        preds = preds.sort_by { |p| p.nil? ? 0 : (p.is_red? ? 2 : 1) }

        if $verbose
          skipped = all_preds - preds
          puts "adding preds #{preds.map{|p|p.idx+1}.inspect} (skipping #{skipped.map{|p|p.idx+1}.inspect})"
        end
        
        preds.each do |p|
          queue.push p
          detected[p] = successor # link from where we found this one
        end
      end
    end

    paths = []
    sources.each do |src|
      trace = []
      cur = src
      
      while not cur.nil?
        trace.push cur
        cur = detected[cur]
      end

      paths.push trace
    end
    
    return paths
  end
  
  @@sources_no_tmp = lambda { |op| ((not op.is_tmp_var?) or op.is_sink?) and (not block_given? or yield op) }
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
  
  attr_reader :func, :var, :from, :preds, :sink_reasons, :line, :idx
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
 -v, -verbose         Verbose mode
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
 -mark-taint          Just mark the taint color of each line
 -no-color            Do not use terminal colors
 -mark-sink [lineno.] Mark the line as sink; this disables automatic sink
                      detection
HELP

taintgrind_trace = false
mark_taint = false
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
  when "-v", "-verbose", "--verbose"
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
  when "-mark-taint"
    mark_taint = true
    ARGV.shift
  when "-no-color"
    $color = false
    ARGV.shift
  when "-mark-sink"
    ARGV.shift
    TaintGrindOp.sink_lines.push ARGV.shift.to_i
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
  
  tgo = TaintGrindOp.new(line, idx, taintgrind_ops)

  if tgo.is_def?
    raise RuntimeError.new("ERROR: Duplicated definition in lines #{taintgrind_ops[tgo.var].idx+1} and #{idx+1}") if taintgrind_ops.has_key?(tgo.var)
    taintgrind_ops[tgo.var] = tgo
  end
  
  if tgo.is_sink?
    sinks.push tgo
  end

  if mark_taint
    print "%8d   " % (tgo.idx+1)
    if $color
      puts(tgo.is_red? ? tgo.line.red : (tgo.is_blue? ? tgo.line.blue : tgo.line.green))
    else
      print(tgo.is_red? ? "[R]  " : (tgo.is_blue? ? "[B]  " : "[G]  "))
      puts tgo.line
    end
  end
end

###### SHOW TRACES ##########

if not mark_taint
  sinks.each_with_index do |sink,sidx|
    if sidx > 0
      # separate each sink
      sep = "=" * 80
      puts($color ? sep.green : sep)
    end
        
    unique_traces_proc = TaintGrindOp.new_sources_unique_traces
    traces = sink.get_traces { |op| (not unique_locs or unique_traces_proc.call(op)) and
                               (not notmp or TaintGrindOp.sources_no_tmp.call(op)) and
                               (not nolib or TaintGrindOp.sources_no_lib.call(op)) }
    traces.each_with_index do |trace,tidx|
      if tidx > 0
        # separate each source
        sep = "-" * 80
        puts($color ? sep.yellow : sep)    
      end
      
      puts ">>>> The origin of the taint should be just here <<<<"
      if src_only
        puts trace[0]
      else
        if mark_trace
          output = input_lines.clone
          trace.each do |n|
            output[n.idx] = [n.is_sink?, n.is_red?, output[n.idx]]
          end
          output.each_with_index do |l,idx|
            print "%8d   " % (idx+1)
            
            if l.is_a? Array
              if $color
                puts(l[0] ? l[2].magenta : (l[1] ? l[2].red : l[2].blue))
              else
                print(l[0] ? "[S]  " : (l[1] ? "[R]  " : "[B]  "))
                puts l[2]
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
    end
  end
end
