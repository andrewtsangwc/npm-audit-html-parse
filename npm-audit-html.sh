#!/bin/bash

# Parameter handling
if [ $# == 0 ]
then
    echo -e "\nUsage: $0 [dev/prod] [dir]\n"
    exit 0
fi

if [ $# != 2 ]
then
    echo -e "\nERROR: Illegal number of parameters.\n"
    exit 1
fi

if [ "$1" != "dev" ] && [ "$1" != "prod" ]
then  
  echo -e "\nERROR: Invalid option of audit mode.\n"
  exit 1
fi

if [ ! -d "$2" ]
then  
  echo -e "\nERROR: Invalid directory.\n"
  exit 1
fi

if [ ! -f "$2/package-lock.json" ]
then  
  echo -e "\nERROR: File package-lock.json not found.\n"
  exit 1
fi

# Declare function for HTML reports
function npm_audit_html() {
    result_file="npm_audit_result-$CI_JOB_ID"
    echo -e "\nDEBUG: Parsing JSON formatted result into HTML format.\n"
    # Base HTML report headings for findings
    result_html="<html><h1>$package_name</h1><p>Analysis Date: $CI_JOB_STARTED_AT&nbsp;&nbsp;&nbsp;&nbsp;CI Job ID: <a href=\"$CI_JOB_URL\">$CI_JOB_ID<a></p><table border=1><thead><th>Name</th><th>Severity</th><th>Via</th><th>Range</th><th>Nodes</th><th>Fix available</th><th>Remarks</th></thead><tbody>"
    # Parse the findings details into HTML
    while IFS= read -r result_line
    do
        result_html="$result_html<tr>"
        result_html="$result_html<td>$(echo $result_line | jq -r .name)</td>"
        result_html="$result_html<td>$(echo $result_line | jq -r .severity)</td>"
        result_html="$result_html<td>"
        via_type=$(echo $result_line | jq -c '.via | map(type)' | jq -r '.[]')
        via_count=$(echo $result_line | jq -r '.via[] | type' | wc -l)
        for (( i=0;i<$(echo $result_line | jq -c '.via | length');i++ ))
        do
            via_type=$(echo $result_line | jq -r --arg i $i '.via[$i | tonumber] | type')
            if [ $via_type == "string" ]
            then
                result_html="$result_html<p><b><u>$(echo $result_line | jq -r --arg i $i '.via[$i | tonumber]')</u></b></p>"
            else
                result_html="$result_html<p><b><u>$(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].name')</u></b></p>"
                result_html="$result_html<ul>"
                result_html="$result_html<li>Dependency: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].dependency')</li>"
                result_html="$result_html<li>Details: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].title')</li>"
                result_html="$result_html<li>Ref: <a href=\"$(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].url')\">$(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].url')</a></li>"
                result_html="$result_html<li>Severity: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].severity')</li>"
                result_html="$result_html<li>CWE: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].cwe | join(", ")')</li>"
                result_html="$result_html<li>CVSS Score: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].cvss.score')</li>"
                result_html="$result_html<li>Range: $(echo $result_line | jq -r --arg i $i '.via[$i | tonumber].range')</li>"
                result_html="$result_html</ul>"
            fi
        done
        result_html="$result_html</td>"
        result_html="$result_html<td>$(echo $result_line | jq -r .range)</td>"
        result_html="$result_html<td>$(echo $result_line | jq -r '.nodes | join("<br>")')</td>"
        result_html="$result_html<td>$(echo $result_line | jq -r '(.fixAvailable | if type == "boolean" then (.|tostring)+"</td><td></td>" else "true</td><td><b>potentially breaking change</b><br>"+.name+"@"+.version end)')</td>"
        result_html="$result_html</tr>"
    done <<< $(echo $npm_audit_json | jq -c '.vulnerabilities[]')
    # Enclosing the HTML report
    result_html="$result_html</tbody></table></html>"
    # Write the JSON formatted report into file
    echo -e "\nDEBUG: Writing the HTML report to report $result_file.json.\n"
    echo $npm_audit_json > "$result_file.json"
    # Write the HTML formatted report into file
    echo -e "\nDEBUG: Writing the HTML report to report $result_file.html.\n"
    echo $result_html > "$result_file.html"

}

# Run npm-audit and output
cd $2
echo -e "\nDEBUG: Performing the NPM audit.\n"
if [ "$1" == "prod" ]
then
  npm audit --omit dev
else
  npm audit
fi

# Early exit if no findings
[ $? == 0 ] && exit 0

# Retrieve the package name and version
echo -e "\nDEBUG: Non-zero NPM audit result. Proceed to reporting and notification.\n"
package_name=$(jq -r '[.name, .version] | join(" v")' package-lock.json)

# Run npm-audit with JSON output option
if [ "$1" == "prod" ]
then
  npm_audit_json=$(npm audit --omit dev --json)
else
  npm_audit_json=$(npm audit --json)
fi
cd -

# Generate HTML report from npm audit result as pipeline artifact
npm_audit_html

# Exit the script with number of severe vulnerabilities (critical & high) to feed back the pipeline
sev_vul=$(($(echo $npm_audit_json | jq '.metadata.vulnerabilities.critical | tonumber')+$(echo $npm_audit_json | jq '.metadata.vulnerabilities.high | tonumber')))
exit $sev_vul
