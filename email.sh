#!/bin/bash
total_tc=$(grep "collected" /root/hpe3par_test_automation/output.log | cut -f2 -d ' ')
failed_tc=0
failed_count=0
cd /root/hpe3par_test_automation/.pytest_cache/v/cache
if [ -a lastfailed ]; then
failed_count=$(cat lastfailed | wc -l)
failed_tc=`expr $failed_count - 1`
else
failed_tc=$failed_count
fi
passed_tc=`expr $total_tc - $failed_tc`
echo "Total Number of Testcases Run    : $total_tc" >> test_summary
echo "Total Number of Testcases Passed : $passed_tc" >> test_summary
echo "Total Number of Testcases Failed : $failed_tc" >> test_summary

