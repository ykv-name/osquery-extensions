/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <osquery/sdk.h>

#include <libiptc/libiptc.h>

namespace trailofbits {
using MatchList = std::vector<std::string>;
using MatchMap = std::map<std::string, MatchList>;

class IptablesExtTable : public osquery::TablePlugin {
 public:
  osquery::TableColumns columns() const;
  osquery::QueryData generate(osquery::QueryContext& context);

 private:
  static osquery::Status genMatchMap(MatchMap& match_map);
  static osquery::Status genIptablesRules(const std::string& filter,
                                          const MatchList& matches,
                                          osquery::QueryData& results);
  static void parseTcpUdpMatch(const xt_entry_match* match, osquery::Row& r);
  static void parseTcp(const xt_entry_match* match, osquery::Row& r);
  static void parseUdp(const xt_entry_match* match, osquery::Row& r);
  static void parseEntryTarget(const xt_entry_target* target, osquery::Row& r);
  static void parseIpEntry(const ipt_ip* ip, osquery::Row& r);
};
} // namespace trailofbits

using IptablesExtTable = trailofbits::IptablesExtTable;
