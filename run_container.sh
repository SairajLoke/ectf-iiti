
# LOGS_PATH=/home/hrishesh/Desktop/ectf/logs/
# docker run --rm -v $LOGS_PATH:/tmp -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

#check wolfssl errors for more details
#warning "For timing resistance / side-channel attack prevention consider using harden options" [-Wcpp]