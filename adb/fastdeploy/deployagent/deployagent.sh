#!/system/bin/sh
base=/data/local/tmp
export CLASSPATH=$base/deployagent.jar
exec app_process $base com.android.fastdeploy.DeployAgent "$@"
