#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

case "$TESTCASE" in
    "versionnegotiation") ;;
    "handshake") ;;
    "transfer") ;;
    "resumption") ;;
    "zerortt") ;;
    "http3") ;;
    "multiconnect") ;;
    *) echo "Unsupported test case: $TESTCASE"; exit 127 ;;
esac

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    TEST_PARAMS="$CLIENT_PARAMS -o /downloads"
    TEST_PARAMS="$TEST_PARAMS -X /logs/keys.log"

    echo "Requests: " $REQUESTS
    for REQ in $REQUESTS; do
        FILE=`echo $REQ | cut -f4 -d'/'`
        echo "parsing <$REQ> as <$FILE>"
        FILELIST=${FILELIST}"-:/"${FILE}";"
    done

    if [ "$TESTCASE" == "http3" ]; then
        TEST_PARAMS="$TEST_PARAMS -a h3-29"
    elif [ "$TESTCASE" == "versionnegotiation" ]; then
        TEST_PARAMS="$TEST_PARAMS -v 5a6a7a8a";
    else
        TEST_PARAMS="$TEST_PARAMS -v ff00001d";
    fi

    if [ "$TESTCASE" == "resumption" ] ||
       [ "$TESTCASE" == "zerortt" ] ; then
            TEST_PARAMS="$TEST_PARAMS -a hq-29"
            FILE1=`echo $FILELIST | cut -f1 -d";"`
            FILE2=`echo $FILELIST | cut -f2- -d";"`
            L1="/logs/first_log.txt"
            L2="/logs/second_log.txt"
            rm *.bin
            /picoquicdemo $TEST_PARAMS server 443 $FILE1 > $L1
            if [ $? != 0 ]; then
                RET=1
                echo "First call to picoquicdemo failed"
            else
                /picoquicdemo $TEST_PARAMS server 443 $FILE2 > $L2
                if [ $? != 0 ]; then
                    RET=1
                    echo "Second call to picoquicdemo failed"
                fi
            fi
    elif [ "$TESTCASE" == "multiconnect" ]; then
        for CREQ in $REQUESTS; do
            CFILE=`echo $CREQ | cut -f4 -d'/'`
            CFILEX="/$CFILE"
            MCLOG="/logs/mc-$CFILE.txt"
            /picoquicdemo $TEST_PARAMS server 443 $CFILEX > $MCLOG
            if [ $? != 0 ]; then
                RET=1
                echo "Call to picoquicdemo failed"
            fi
        done
    else
        /picoquicdemo $TEST_PARAMS server 443 $FILELIST > /logs/client.log
    fi
elif [ "$ROLE" == "server" ]; then
    TEST_PARAMS="$SERVER_PARAMS -k /certs/key.pem"
    TEST_PARAMS="$TEST_PARAMS -c /certs/cert.pem"
    TEST_PARAMS="$TEST_PARAMS -p 443"
    TEST_PARAMS="$TEST_PARAMS -X /logs/keys.log"
    TEST_PARAMS="$TEST_PARAMS -w /www"
    /picoquicdemo $TEST_PARAMS > /logs/server.log
fi