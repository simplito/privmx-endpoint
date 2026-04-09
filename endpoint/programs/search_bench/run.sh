#!/bin/bash
PRIV_KEY="L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"
CONTEXT_ID="edfcb422-6428-48c1-b52b-7be4b673a170"
SOLUTION_ID="ab7ac88f-f611-4cb2-b163-5308a05b67dc"
BRIDGE_URL="http://localhost:9111"
DOCS_DIR="/home/zurek/search_bench"
cd ../../../build/endpoint/programs/search_bench || exit
./search_bench $PRIV_KEY $SOLUTION_ID $BRIDGE_URL $CONTEXT_ID $DOCS_DIR