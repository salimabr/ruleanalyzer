
# Name: ruleanalyzer.py
# Author: Michael Miranda

import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("rules", help="path to the rules file to analyze")
parser.add_argument("--report", help="rule field to print: action,protocol,source,source_port,destination,destination_port,header,option")
parser.add_argument("--criteria", help="string criteria that needs to match a field in the report output that will initiate the printing of the rule")
args = parser.parse_args()
#print(args.rules)

#rules = open('rules/community-rules/community.rules')
#rules = open('rules/emerging-all.rules')

rules = open(args.rules)
rule = rules.readline()
raw_count = 0
count = 0
while rule: 
	raw_count = raw_count + 1
	if not rule.startswith("#") and not rule.startswith("\n"):
		count = count + 1
		space_tokens = re.split(" +", rule)
		action = space_tokens[0]
		protocol = space_tokens[1]
		source = space_tokens[2]
		source_port = space_tokens[3]
		direction = space_tokens[4]
		destination = space_tokens[5]
		destination_port = space_tokens[6]
		header = action + " " + protocol + " " + source + " " + source_port + " " + direction + " " + destination + " " + destination_port + " "
		options_arr = re.split(" \(", rule)
		options = re.sub("\)$", "", options_arr[1])
		if args.report == "action":
			if args.criteria is not None and args.criteria in action:
				print(action + ": " + rule)
			elif args.criteria is None:
				print(action)
		elif args.report == "protocol":
			if args.criteria is not None and args.criteria in protocol:
				print(protocol + ": " + rule)
			elif args.criteria is None:
				print(protocol)
		elif args.report == "source":
			source_split = re.sub("\[", "", source)
			source_split = re.sub("\]", "", source_split)
			sources = source_split.split(",")
			for src in sources:
				if args.criteria is not None and args.criteria in src:
					print(src + ": " + rule)
				elif args.criteria is None:
					print(src)
		elif args.report == "source_port":
			source_port_split = re.sub("\[", "", source_port)
			source_port_split = re.sub("\]", "", source_port_split)
			source_ports = source_port_split.split(",")
			for src_port in source_ports:
				if args.criteria is not None and args.criteria in src_port:
					print(src_port + ": " + rule)
				elif args.criteria is None:
					print(src_port)
		elif args.report == "direction":
			if args.criteria is not None and args.criteria in direction:
				print(direction + ": " + rule)
			elif args.criteria is None:
				print(direction)
		elif args.report == "destination":
			destination_split = re.sub("\[", "", destination)
			destination_split = re.sub("\]", "", destination_split)
			destinations = destination_split.split(",")
			for dst in destinations:
				if args.criteria is not None and args.criteria in dst:
					print(dst + ": " + rule)
				elif args.criteria is None:
					print(dst)
		elif args.report == "destination_port":
			destination_port_split = re.sub("\[", "", destination_port)
			destination_port_split = re.sub("\]", "", destination_port_split)
			destination_ports = destination_port_split.split(",")
			for dst_port in destination_ports:
				if args.criteria is not None and args.criteria in dst_port:
					print(dst_port + ": " + rule)
				elif args.criteria is None:
					print(dst_port)
		elif args.report == "header":
			if args.criteria is not None and args.criteria in header:
				print(header + ": " + rule)
			elif args.criteria is None:
				print(header)
		elif args.report == "option":
			field_values = options.split("; ")
			for field_value in field_values:
				if args.criteria is not None and args.criteria in field_value:
					print(field_value + ": " + rule)
				elif args.criteria is None:
					print(field_value)
	rule = rules.readline()
rules.close()

