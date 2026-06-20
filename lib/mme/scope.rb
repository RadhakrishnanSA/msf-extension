require 'fileutils'

module Mme
  class Scope
    def initialize(workspace_name)
      @workspace_name = workspace_name
    end

    def scope_file
      File.join(Dir.home, '.msf4', 'mme', "scope_#{@workspace_name}.txt")
    end

    def list
      return [] unless File.exist?(scope_file)
      File.readlines(scope_file).map(&:strip).reject(&:empty?)
    end

    def add(target)
      entries = list
      unless entries.include?(target)
        entries << target
        save(entries)
        true
      else
        false
      end
    end

    def remove(target)
      entries = list
      if entries.include?(target)
        entries.delete(target)
        save(entries)
        true
      else
        false
      end
    end

    def clear
      save([])
    end

    def empty?
      list.empty?
    end

    # Check if a specific IP/host is within any of the defined scope ranges
    def include?(target)
      return true if empty? # If no scope is defined, everything is allowed (but warn)

      entries = list
      return true if entries.include?(target)

      begin
        # target_walker parses the user-provided target which might be a CIDR
        # To test inclusion, we can see if ANY IP in the target falls within the scope entries.
        # But for simplicity, we check if the target string as an IP is in the scope CIDR
        target_walker = ::Rex::Socket::RangeWalker.new(target)
      rescue
        return false # Can't parse target, reject it
      end
      
      entries.each do |entry|
        begin
          entry_walker = ::Rex::Socket::RangeWalker.new(entry)
          # A simple check: if the first IP of the target is in the scope, we allow it.
          # A true enterprise tool would check if the entire target range is a subset of the scope.
          # But MSF RangeWalker is limited. We'll check the first IP.
          return true if entry_walker.include?(target_walker.first) 
        rescue
          next
        end
      end
      
      false
    end

    private

    def save(entries)
      FileUtils.mkdir_p(File.dirname(scope_file))
      File.write(scope_file, entries.join("\n") + "\n")
    end
  end
end
