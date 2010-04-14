#! /bin/sh

# This script parses /var/log/syslog for messages from programs that log
# uptime and disk stats (number of sectors read).  It then outputs
# these stats in a format usable by the metrics collector, which forwards
# them to autotest and UMA.

# To add a new metric add a line below, as PROGRAM_NAME  METRIC_NAME.
# PROGRAM_NAME is the name of the job whose start time we
# are interested in.  METRIC_NAME is the prefix we want to use for
# reporting to UMA and autotest.  The script prepends "Time" and
# "Sectors" to METRIC_NAME for the two available measurements, uptime
# and number of sectors read thus far.

# You will need to emit messages similar to the following in order to add a 
# a metric using this process.  You will need to emit both a start and stop
# time and the metric reported will be the difference in values

# Nov 15 08:05 localhost PROGRAM_NAME[822]: start METRIC_NAME time 12 sectors 56
# Nov 15 08:05 localhost PROGRAM_NAME[822]: stop METRIC_NAME time 24 sectors 68

# If you add metrics without a start, it is assumed you are requesting the
# time differece from system start

# Metrics we are interested in measuring
METRICS="
upstart start_x
"

first=1
program=""

# Get the metrics for all things
for m in $METRICS
do
  if [ $first -eq 1 ]
  then
    first=0
    program_name=$m 
  else
    first=1
    metrics_name=$m       
         
    # Example of line from /var/log/messages:
    # Nov 15 08:05:42 localhost connmand[822]: start metric time 12 sectors 56
    # "upstart:" is $5, 1234 is $9, etc.
    program="${program}/$program_name([[0-9]+]:|:) start $metrics_name/\
    {
      metrics_start[\"${metrics_name}Time\"] = \$9;
      metrics_start[\"${metrics_name}Sectors\"] = \$11;            
    }"
    program="${program}/$program_name([[0-9]+]:|:) stop $metrics_name/\
    { 
        metrics_stop[\"${metrics_name}Time\"] = \$9;
        metrics_stop[\"${metrics_name}Sectors\"] = \$11;
    }"
  fi      
done

# Do all the differencing here
program="${program}\
END{
  for (i in metrics_stop) {
    value_time = metrics_stop[i] - metrics_start[i];
    print i \"=\" value_time;
  }
}"

exec awk "$program" /var/log/syslog