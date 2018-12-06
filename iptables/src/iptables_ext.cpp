/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk.h>

#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>
#include <netdb.h>
#include <sstream>

#include <boost/algorithm/string/trim.hpp>

#include <trailofbits/extutils.h>

#include "iptables_ext.h"
#include "utils.h"

// Prepends a "!" to the given string if flag is present in the
// given struct's invert flags.
// NOTE(ww): Experimentally, it looks like recent versions of iptables
// don't use these flags much -- they only seem to get set on the protocol
// and a few other fields, with other fields receiving a mask instead.
#define FLAGNEGATE(x, flag, str)                                               \
  ((((x)->invflags) & (flag)) ? "!" + (str) : (str))

using namespace osquery;

namespace trailofbits {
static const std::string kLinuxIpTablesNames = "/proc/net/ip_tables_names";
static const std::string kHexMap = "0123456789ABCDEF";

static const int kMaskHighBits = 4;
static const int kMaskLowBits = 15;

osquery::TableColumns IptablesExtTable::columns() const {
  return {
      std::make_tuple("filter_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("chain", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("ruleno", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("target", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("match", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("protocol", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_port", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_port", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_ip", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("iniface", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("iniface_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_ip", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("outiface", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("outiface_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("packets", BIGINT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("bytes", BIGINT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("reject_with", TEXT_TYPE, ColumnOptions::DEFAULT),
  };
}

osquery::QueryData IptablesExtTable::generate(osquery::QueryContext& context) {
  osquery::QueryData results;

  MatchMap match_map;
  auto s = genMatchMap(match_map);

  if (!s.ok()) {
    TLOG << "Error fetching matches from iptables-save: " << s.toString();
  }

  // Read in table names
  std::string content;
  s = osquery::readFile(kLinuxIpTablesNames, content);
  if (s.ok()) {
    for (auto& line : SplitString(content, '\n')) {
      boost::algorithm::trim(line);
      if (line.size() > 0) {
        const auto matches = match_map.find(line);

        if (matches == match_map.end()) {
          TLOG << "Couldn't associate table " << line
               << " with a list of matches";
          return results;
        }

        s = genIptablesRules(line, matches->second, results);

        if (!s.ok()) {
          TLOG << "Error while fetching table rules: " << s.toString();
          // TODO(ww): Return early here or keep trying lines?
          return results;
        }
      }
    }
  } else {
    // Permissions issue or iptables modules are not loaded.
    TLOG << "Error reading " << kLinuxIpTablesNames << " : " << s.toString();
  }

  return results;
}

osquery::Status IptablesExtTable::genMatchMap(MatchMap& match_map) {
  ProcessOutput output;

  if (!ExecuteProcess(output, "/sbin/iptables-save", {}) ||
      output.exit_code != 0) {
    return osquery::Status(1, "couldn't exec /sbin/iptables-save");
  }

  if (output.std_output.empty()) {
    return osquery::Status(1, "no output from iptables-save");
  }

  std::string table;
  for (auto line : SplitString(output.std_output, '\n')) {
    // If the line is a comment or just a chain name, skip it.
    if (line.at(0) == '#' || line.at(0) == ':') {
      continue;
    }

    // If the line is a filter name, record it and prep our map with it.
    if (line.at(0) == '*') {
      table = line.substr(1);
      match_map[table];
      continue;
    }

    // If the line is a rule, look for match entries within it.
    if (line.find("-A") == 0) {
      // Matches begin with an -m.
      auto start = line.find("-m");

      if (start == std::string::npos) {
        match_map[table].push_back("");
      } else {
        auto stop = line.find("-j", start + 1);

        // If we can't find the beginning of a jump option, look for a
        // goto option.
        if (stop == std::string::npos) {
          stop = line.find("-g", start + 1);
        }

        // Sanity check for a valid substring.
        if (stop != std::string::npos && stop < start) {
          TLOG << "Oddity: -j or -g before -m: " << line;
          match_map[table].push_back("");
        } else {
          match_map[table].push_back(line.substr(start, stop - start - 1));
        }
      }
    }
  }

  return osquery::Status(0);
}

osquery::Status IptablesExtTable::genIptablesRules(
    const std::string& filter,
    const MatchList& matches,
    osquery::QueryData& results) {
  // Initialize the access to iptc
  auto handle = static_cast<iptc_handle*>(iptc_init(filter.c_str()));
  if (handle == nullptr) {
    osquery::Status(1, "Couldn't initialize iptables handle");
  }

  // Iterate through chains
  for (auto chain = iptc_first_chain(handle); chain != nullptr;
       chain = iptc_next_chain(handle)) {
    // NOTE(ww): Rules are 1-based in libiptc, as evidenced by
    // iptc_read_counter.
    unsigned long ruleno = 1;
    // Iterating through all the rules per chain
    for (const ipt_entry* chain_rule = iptc_first_rule(chain, handle);
         chain_rule != nullptr;
         chain_rule = iptc_next_rule(chain_rule, handle)) {
      osquery::Row r;

      r["filter_name"] = filter;
      r["chain"] = TEXT(chain);
      r["packets"] = BIGINT(chain_rule->counters.pcnt);
      r["bytes"] = BIGINT(chain_rule->counters.bcnt);
      r["ruleno"] = INTEGER(ruleno);
      r["target"] = TEXT(iptc_get_target(chain_rule, handle));

      if (ruleno - 1 < matches.size()) {
        r["match"] = TEXT(matches[ruleno - 1]);
      } else {
        TLOG << "rule number mismatch!";
        r["match"] = "";
      }

      if (chain_rule->target_offset) {
        auto target = reinterpret_cast<const xt_entry_target*>(
            reinterpret_cast<const char*>(chain_rule) +
            chain_rule->target_offset);
        parseEntryTarget(target, r);

        // This is basically the IPT_MATCH_ITERATE macro from iptables,
        // but without the GNU C magic (void pointer arithmetic,
        // macro expression extensions).
        const xt_entry_match* match;
        for (int i = sizeof(ipt_entry); i < chain_rule->target_offset;
             i += match->u.match_size) {
          match = reinterpret_cast<const xt_entry_match*>(
              reinterpret_cast<const char*>(chain_rule) + i);
          parseTcpUdpMatch(match, r);
        }
      } else {
        r["src_port"] = "";
        r["dst_port"] = "";
      }

      const ipt_ip* ip = &chain_rule->ip;
      parseIpEntry(ip, r);

      results.push_back(r);
      ruleno++;
    } // Rule iteration
  } // Chain iteration

  iptc_free(handle);

  return osquery::Status(0);
}

void IptablesExtTable::parseTcpUdpMatch(const xt_entry_match* match,
                                        osquery::Row& r) {
  std::string match_name(match->u.user.name);

  if (match_name == "tcp") {
    parseTcp(match, r);
  } else if (match_name == "udp") {
    parseUdp(match, r);
  }
}

void IptablesExtTable::parseTcp(const xt_entry_match* match, osquery::Row& r) {
  auto tcp = reinterpret_cast<const ipt_tcp*>(match->data);

  std::string src_port =
      std::to_string(tcp->spts[0]) + ':' + std::to_string(tcp->spts[1]);
  r["src_port"] = FLAGNEGATE(tcp, IPT_TCP_INV_SRCPT, src_port);

  std::string dst_port =
      std::to_string(tcp->dpts[0]) + ':' + std::to_string(tcp->dpts[1]);
  r["dst_port"] = FLAGNEGATE(tcp, IPT_TCP_INV_DSTPT, dst_port);
}

void IptablesExtTable::parseUdp(const xt_entry_match* match, osquery::Row& r) {
  auto udp = reinterpret_cast<const ipt_udp*>(match->data);

  std::string src_port =
      std::to_string(udp->spts[0]) + ':' + std::to_string(udp->spts[1]);
  r["src_port"] = FLAGNEGATE(udp, IPT_UDP_INV_SRCPT, src_port);

  std::string dst_port =
      std::to_string(udp->dpts[0]) + ':' + std::to_string(udp->dpts[1]);
  r["dst_port"] = FLAGNEGATE(udp, IPT_UDP_INV_DSTPT, dst_port);
}

void IptablesExtTable::parseEntryTarget(const xt_entry_target* target,
                                        osquery::Row& r) {
  std::string target_name(target->u.user.name);

  // NOTE(ww): REJECT is the only special-case target for now,
  // but there might be others. What information do the other
  // targets store in their `data` fields?
  if (target_name == "REJECT") {
    auto reject = reinterpret_cast<const ipt_reject_info*>(target->data);
    std::string with;

    switch (reject->with) {
    case IPT_ICMP_NET_UNREACHABLE: {
      with = "IPT_ICMP_NET_UNREACHABLE";
      break;
    }
    case IPT_ICMP_HOST_UNREACHABLE: {
      with = "IPT_ICMP_HOST_UNREACHABLE";
      break;
    }
    case IPT_ICMP_PROT_UNREACHABLE: {
      with = "IPT_ICMP_PROT_UNREACHABLE";
      break;
    }
    case IPT_ICMP_PORT_UNREACHABLE: {
      with = "IPT_ICMP_PORT_UNREACHABLE";
      break;
    }
    case IPT_ICMP_ECHOREPLY: {
      with = "IPT_ICMP_ECHOREPLY";
      break;
    }
    case IPT_ICMP_NET_PROHIBITED: {
      with = "IPT_ICMP_NET_PROHIBITED";
      break;
    }
    case IPT_ICMP_HOST_PROHIBITED: {
      with = "IPT_ICMP_HOST_PROHIBITED";
      break;
    }
    case IPT_TCP_RESET: {
      with = "IPT_TCP_RESET";
      break;
    }
    case IPT_ICMP_ADMIN_PROHIBITED: {
      with = "IPT_ICMP_ADMIN_PROHIBITED";
      break;
    }
    default: {
      with = "UNKNOWN";
      TLOG << "Weird rejection method: " << reject->with;
    }
    }

    r["reject_with"] = with;
  }
}

void IptablesExtTable::parseIpEntry(const ipt_ip* ip, osquery::Row& r) {
  protoent* pent = getprotobynumber(ip->proto);

  std::string protocol;
  if (pent) {
    protocol = TEXT(pent->p_name);
  } else {
    protocol = TEXT(ip->proto);
  }
  r["protocol"] = FLAGNEGATE(ip, IPT_INV_PROTO, protocol);

  std::string iniface;
  if (strlen(ip->iniface)) {
    iniface = FLAGNEGATE(ip, IPT_INV_VIA_IN, TEXT(ip->iniface));
  } else if (ip->invflags & IPT_INV_VIA_IN) {
    // NOTE(ww): This shouldn't be possible via the `iptables` CLI,
    // but who knows?
    iniface = "none";
  } else {
    iniface = "all";
  }
  r["iniface"] = iniface;

  std::string outiface;
  if (strlen(ip->outiface)) {
    outiface = FLAGNEGATE(ip, IPT_INV_VIA_OUT, TEXT(ip->outiface));
  } else if (ip->invflags & IPT_INV_VIA_OUT) {
    // NOTE(ww): This shouldn't be possible via the `iptables` CLI,
    // but who knows?
    outiface = "none";
  } else {
    outiface = "all";
  }
  r["outiface"] = outiface;

  r["src_ip"] = FLAGNEGATE(ip, IPT_INV_SRCIP, ipAsString(&ip->src));
  r["dst_ip"] = FLAGNEGATE(ip, IPT_INV_DSTIP, ipAsString(&ip->dst));
  r["src_mask"] = ipAsString(&ip->smsk);
  r["dst_mask"] = ipAsString(&ip->dmsk);

  char aux_char[2] = {0};
  std::string iniface_mask;
  for (int i = 0; i < IFNAMSIZ && ip->iniface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[ip->iniface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[ip->iniface_mask[i] & kMaskLowBits];
    iniface_mask += aux_char[0];
    iniface_mask += aux_char[1];
  }
  r["iniface_mask"] = TEXT(iniface_mask);

  std::string outiface_mask = "";
  for (int i = 0; i < IFNAMSIZ && ip->outiface_mask[i] != 0x00; i++) {
    aux_char[0] = kHexMap[ip->outiface_mask[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[ip->outiface_mask[i] & kMaskLowBits];
    outiface_mask += aux_char[0];
    outiface_mask += aux_char[1];
  }
  r["outiface_mask"] = TEXT(outiface_mask);
}

} // namespace trailofbits

#undef FLAGNEGATE
