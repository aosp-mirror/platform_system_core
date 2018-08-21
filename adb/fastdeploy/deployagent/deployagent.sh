# Script to start "deployagent" on the device, which has a very rudimentary
# shell.
#
base=/data/local/tmp
export CLASSPATH=$base/deployagent.jar
exec app_process $base com.android.fastdeploy.DeployAgent "$@"

