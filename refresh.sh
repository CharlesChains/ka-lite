kalite stop
current_dir=$(pwd)
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
cd $SCRIPTPATH
python setup.py install
pip install -e .
kalite manage setup
cd $current_dir
