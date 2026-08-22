description = [[
For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

Its work is pretty simple:
* work only when some software version is identified for an open port
* take all the known CPEs for that software (from the standard nmap -sV output)
* make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
* if no info is found this way, try to get it using the software name alone
* print the obtained info out

NB:
Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db.
So we do make requests to a remote service. Still all the requests contain just two fields - the
software name and its version (or CPE), so one can still have the desired privacy.

NB2:
This script requires a valid API token. You can either specify it on the CLI using the 'api_key' script argument,
set it into an envirotnment variable VULNERS_API_KEY, or store it in a file readable by the user running nmap. 
In this case you must specify the absolute path to the file using the 'api_key_file' script argument.
]]

---
-- @usage
-- nmap -sV --script vulners_enterprise [--script-args mincvss=<arg_val>,api_key=<api_key>,api_key_file=<absolute_path>,api_host=http://my_host.com] <target>
--
-- @args vulners_enterprise.mincvss Limit CVEs shown to those with this CVSS score or greater.
-- @args vulners_enterprise.api_key API token to be used in the requests
-- @args vulners_enterprise.api_key_file Absolute path to the file with a single line containing the API token
-- @args vulners_enterprise.api_host domain name to vulners API. Defaults to vulners.com
-- @args vulners_enterprise.api_port port number on the api_host. Defaults to 443
--
-- @output
--
-- 22/tcp open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
-- | vulners_enterprise:
-- |   cpe:/a:openbsd:openssh:7.4:
-- |            F0979183-AE88-53B4-86CF-3AF0523F3807    cvss3.1: 9.8    https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807  *HAS EXPLOIT*
-- |            CVE-2023-38408  cvss3.1: 9.8    https://vulners.com/cve/CVE-2023-38408
-- |            B8190CDB-3EB9-5631-9828-8064A1575B23    cvss3.1: 9.8    https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23  *HAS EXPLOIT*
-- |            8FC9C5AB-3968-5F3C-825E-E8DB5379A623    cvss3.1: 9.8    https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623  *HAS EXPLOIT*
-- |            8AD01159-548E-546E-AA87-2DE89F3927EC    cvss3.1: 9.8    https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC  *HAS EXPLOIT*
-- |            5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    cvss3.1: 9.8    https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A  *HAS EXPLOIT*
-- |            2227729D-6700-5C8F-8930-1EEAFD4B9FF0    cvss3.1: 9.8    https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0  *HAS EXPLOIT*
-- |            0221525F-07F5-5790-912D-F4B9E2D1B587    cvss3.1: 9.8    https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587  *HAS EXPLOIT*
-- |            54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    cvss3.1: 5.9    https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C  *HAS EXPLOIT*
-- |            EDB-ID:45939    cvss3.1: 5.3    https://vulners.com/exploitdb/EDB-ID:45939      *HAS EXPLOIT*
-- |            EDB-ID:45233    cvss3.1: 5.3    https://vulners.com/exploitdb/EDB-ID:45233      *HAS EXPLOIT*
-- |            CVE-2018-20685  cvss3.1: 5.3    https://vulners.com/cve/CVE-2018-20685
-- |            CVE-2018-15919  cvss3.0: 5.3    https://vulners.com/cve/CVE-2018-15919
-- |            CVE-2018-15473  cvss3.1: 5.3    https://vulners.com/cve/CVE-2018-15473
-- |            CVE-2017-15906  cvss3.1: 5.3    https://vulners.com/cve/CVE-2017-15906
-- |            CVE-2016-20012  cvss3.1: 5.3    https://vulners.com/cve/CVE-2016-20012
-- |            CVE-2025-32728  cvss3.1: 4.3    https://vulners.com/cve/CVE-2025-32728
-- |_           CVE-2021-36368  cvss3.1: 3.7    https://vulners.com/cve/CVE-2021-36368
--
-- @xmloutput
-- <table key="cpe:/a:openbsd:openssh:7.4">
-- <table>
--   <elem key="cvss">9.8</elem>
--   <elem key="id">F0979183-AE88-53B4-86CF-3AF0523F3807</elem>
--   <elem key="type">githubexploit</elem>
--   <elem key="is_exploit">true</elem>
--   <elem key="cvss_type">cvss3.1</elem>
-- </table>
-- <table>
--   <elem key="id">CVE-2023-38408</elem>
--   <elem key="type">cve</elem>
--   <elem key="cvss">9.8</elem>
--   <elem key="cvss_type">cvss3.1</elem>
-- </table>
-- </table>

dependencies = {"http-vulners-regex"}
author = 'gmedian AT vulners DOT com'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external", "default"}


local http = require "http"
local url = require "url"
local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"
local os = require "os"

local api_version="1.11"
local mincvss=stdnse.get_script_args(SCRIPT_NAME .. ".mincvss")
mincvss = tonumber(mincvss) or 0.0

local api_key_file=stdnse.get_script_args(SCRIPT_NAME .. ".api_key_file")
api_key_file = api_key_file or ""

local api_host=stdnse.get_script_args(SCRIPT_NAME .. ".api_host")
api_host = api_host or 'vulners.com'

local api_port=stdnse.get_script_args(SCRIPT_NAME .. ".api_port")
api_port = api_port or 443

local api_key=stdnse.get_script_args(SCRIPT_NAME .. ".api_key")
api_key = api_key or os.getenv("VULNERS_API_KEY")

portrule = function(host, port)
  local vers=port.version
  return vers ~= nil and vers.version ~= nil or (host.registry.vulners_cpe ~= nil)
end

local cve_meta = {
  __tostring = function(me)
      return ("\t%s\t%s: %s\thttps://vulners.com/%s/%s%s"):format(me.id, me.cvss_type, me.cvss or "", me.type, me.id, me.is_exploit and '\t*HAS EXPLOIT*' or '')
  end,
}


---
-- Return a string read from api_key_file to be used as an API_KEY
--
function read_api_key_file()

  stdnse.debug1("api_key not specified. Trying to read api_key_file.")

  if api_key_file == nil or api_key_file == "" then
    stdnse.debug1("No api_key_file set")
    return ""
  end

  local file = io.open(api_key_file, "r")
  if file == nil then
    stdnse.debug1("Failed to open api_key_file " .. api_key_file)
    return ""
  end

  api_key = file:read("*line")

  file:close()

  return api_key
end


---
-- Return a string with all the found cve's and correspondent links
--
-- @param vulns a table list of vulnerabilities from the parsed json response from the vulners server
--
function make_links(vulns)
  local output = {}
  local exploit_types = {"exploitdb", "githubexploit", "metasploit", "packetstorm"}

  if not vulns then
    return
  end

  for _, vuln in ipairs(vulns) do

    local v = {
      id = vuln.id,
      type = vuln.type
    }
        -- Sometimes it might happen, so check the score availability
    if vuln.metrics.cvss ~= nil then
      v['cvss'] = vuln.metrics.cvss.score
      v['cvss_type'] = "cvss" .. vuln.metrics.cvss.version
    end

    for _, ref in ipairs(vuln.enchantments.dependencies.references) do
      for __, type in ipairs(exploit_types) do
        if ref.type == type then
          for ___, exploitId in ipairs(ref.idList) do
            local expl = {
              id = exploitId,
              type = ref.type,
              -- Mark the exploits out
              is_exploit = true,
              cvss = v.cvss,
              cvss_type = v.cvss_type
            }
            setmetatable(expl, cve_meta)
            output[#output+1] = expl
          end
          goto L2
        end
      end
    end

::L2::

    -- NOTE[gmedian]: exploits seem to have cvss == 0, so print them anyway
    if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
      setmetatable(v, cve_meta)
      output[#output+1] = v
    end
  end

  if #output > 0 then
    -- Sort the acquired vulns by the CVSS score
    table.sort(output, function(a, b)
        return a.cvss > b.cvss or (a.cvss == b.cvss and a.id > b.id)
      end)
    return output
  end
end


---
-- Issues the requests, receives json and parses it, calls <code>make_links</code> when successfull
--
-- @param what table, future value for the software query argument
--
function get_results(what)
  local api_endpoint = "/api/v4/audit/software/"
  local vulns
  local response
  local status
  local attempt_n=0
  local postbody = {
          software={what},
          fields={'type', 'metrics', 'enchantments'}
  }

  -- local api_url = ('%s?%s'):format(api_endpoint, url.build_query(query))
  local option={
    header={
      ['User-Agent'] = string.format('Vulners NMAP Enterprise %s', api_version),
      ['Accept-Encoding'] = "gzip, deflate",
      ['Content-Type'] = "application/json",
      ['X-Api-Key'] = api_key
    },
    any_af = true,
  }

  postbody = json.generate(postbody)

  stdnse.debug1("Trying to send data " .. postbody)

  -- Sometimes we cannot contact vulners, so have to try several more times
  while attempt_n < 3 do
    stdnse.debug1("Attempt ".. attempt_n .. " to contact vulners.")
    response = http.post(api_host, api_port, api_endpoint, option, nil, postbody)
    status = response.status
    if status ~= nil then
      break
    end
    attempt_n = attempt_n + 1
    stdnse.sleep(1)
  end

  if status == nil then
    -- Something went really wrong out there
    -- According to the NSE way we will die silently rather than spam user with error messages
    stdnse.debug1("Failed to contact vulners in several attempts.")
    return
  elseif status ~= 200 then
    -- Again just die silently
    stdnse.debug1("Response from vulners is not 200 but " .. status)
    return
  end

  status, resp_body = json.parse(response.body)

  if status == true then
    stdnse.debug1("Have successfully parsed json response.")
    if #resp_body.result > 0 then
      stdnse.debug1("Response from vulners is OK.")
      return make_links(resp_body.result[1].vulnerabilities)
    else
      stdnse.debug1("Response from vulners is not OK with body:")
      stdnse.debug1(response.body)
    end
  else
    stdnse.debug1("Unable to parse json.")
    stdnse.debug1(response.body)
  end
end


---
-- Calls <code>get_results</code> for type="software"
--
-- It is called from <code>action</code> when nothing is found for the available cpe's
--
-- @param software string, the software name
-- @param version string, the software version
--
function get_vulns_by_software(software, version)
  local what = {
    ['product'] = software,
    ['version'] = version,
  }
  return get_results(what)
end


---
-- Calls <code>get_results</code> for type="cpe"
--
-- Takes the version number from the given <code>cpe</code> and tries to get the result.
-- Having failed returns an empty string.
--
-- @param cpe string, the given cpe
--
function get_vulns_by_cpe(cpe)
  -- cpe:/a:openbsd:openssh:7.4
  -- local cpe_regexp=":([%d%.%-%_]+)([^:]*)$"
  local cpe_regexp="^cpe:/(%l):([^:]+):([^:]+):([%d%.%-%_]+)([^:]*)$"


  -- TODO[gmedian]: add check for cpe:/a  as we might be interested in software rather than in OS (cpe:/o) and hardware (cpe:/h)
  -- TODO[gmedian]: work not with the LAST part but simply with the THIRD one (according to cpe doc it must be version)

  -- NOTE[gmedian]: take only the numeric part of the version
  local _, _, part, vendor, product, vers, update = cpe:find(cpe_regexp)

  if not vers then
    return
  end

  stdnse.debug1("Got cpe " .. cpe .. " with part " .. part .. " vendor " .. vendor .. " product " .. product .. " version ".. vers .. " and update " .. (update or "nil"))

  local what = {
    ['part'] = part,
    ['vendor'] = vendor,
    ['product'] = product,
    ['version'] = vers,
    ['update'] = update
  }

  local output = get_results(what)

  return output
end


action = function(host, port)
  local tab=stdnse.output_table()
  local changed=false
  local output
  
  api_key = api_key or read_api_key_file()

  if api_key == nil or api_key == "" then
    stdnse.debug1("Api key is not set in either arg, ENV or file. Exiting.")
    return
  end

  stdnse.debug1("Api file is set to " .. api_key_file)
  stdnse.debug1("Host is set to " .. api_host)
  stdnse.debug1("Port is set to " .. api_port)
  stdnse.debug1("Api key is set to " .. api_key)

  for i, cpe in ipairs(port.version.cpe) do
    -- There are two cpe's for nginx, have to check them both
    cpe = cpe:gsub(":nginx:nginx", ":igor_sysoev:nginx")
    stdnse.debug1("Analyzing cpe " .. cpe)
    output = get_vulns_by_cpe(cpe)
    if cpe:find(":igor_sysoev:nginx") then
      cpe = cpe:gsub(":igor_sysoev:nginx", ":nginx:nginx")
      stdnse.debug1("Now going to analyze the second version " .. cpe)
      local output_nginx=get_vulns_by_cpe(cpe)
      if not output then
        output = output_nginx
      elseif output_nginx then
        -- Need to merge two arrays, sorted by cvss
        -- Presumably the former output contains by far less entries, so iterate on it and insert into the latter
        -- pos will represent current position in output_nginx
        local pos=1
        for i, v in ipairs(output) do
          while pos <= #output_nginx and output_nginx[pos].cvss >= v.cvss do
              pos = pos + 1
          end
          table.insert(output_nginx, pos, v)
        end
        output = output_nginx
      end
    end
    if output then
      tab[cpe] = output
      changed = true
    end
  end
  
  -- NOTE[gmedian]: check whether we have pre-matched CPEs in registry (from http-vulners-regex.nse in particular)
  if host.registry.vulners_cpe ~= nil and #host.registry.vulners_cpe > 0 then 
    stdnse.debug1("Found some CPEs in host registry.")
    for i, cpe in ipairs(host.registry.vulners_cpe) do
      -- avoid duplicates in output, will still however make redundant requests
      if tab[cpe] == nil then
        stdnse.debug1("Analyzing pre-matched cpe " .. cpe)
        output = get_vulns_by_cpe(cpe)
        if output then
          tab[cpe] = output
          changed = true
        end
      end
    end
  end

  -- NOTE[gmedian]: issue request for type=software, but only when nothing is found so far
  if not changed then
    local vendor_version = port.version.product .. " " .. port.version.version
    output = get_vulns_by_software(port.version.product, port.version.version)
    if output then
      tab[vendor_version] = output
      changed = true
    end
  end

  if (not changed) then
    return
  end
  return tab
end

