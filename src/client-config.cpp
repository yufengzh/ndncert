/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "client-config.hpp"
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {

void
ClientConfig::load(const std::string& fileName)
{
  try {
    boost::property_tree::read_json(fileName, m_config);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + fileName +
                                " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (m_config.begin() == m_config.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + fileName + " no data"));
  }

  parse();
}

void
ClientConfig::parse()
{
  m_caItems.clear();
  auto caList = m_config.get_child("ca-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    ClientCaItem item;
    item.m_caName = Name(it->second.get<std::string>("ca-prefix"));
    item.m_caInfo = it->second.get<std::string>("ca-info");
    item.m_probe = it->second.get("probe", "");

    std::istringstream ss(it->second.get<std::string>("certificate"));
    item.m_anchor = *(io::load<security::v2::Certificate>(ss));

    auto challengeList = it->second.get_child("supported-challenges");
    item.m_supportedChallenges = parseChallengeList(challengeList);

    m_caItems.push_back(item);
  }
}

std::list<std::string>
ClientConfig::parseChallengeList(const JsonSection& section)
{
  std::list<std::string> result;
  auto it = section.begin();
  for (; it != section.end(); it++) {
    result.push_back(it->second.get<std::string>("type"));
  }
  return result;
}

void
ClientConfig::addNewCaItem(const ClientCaItem& item)
{
  m_caItems.push_back(item);
}

void
ClientConfig::removeCaItem(const Name& caName)
{
  m_caItems.remove_if([&] (const ClientCaItem& item) {return item.m_caName == caName;});
}

} // namespace ndncert
} // namespace ndn