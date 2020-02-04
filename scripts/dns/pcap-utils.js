function PcapPacket(bytes, captureLen, network, transport) {
  this.data = bytes;
  this.size = captureLen+16; //+tcpdump header: ts_sec, ts_usec, incl_len, orig_len
  this.payloadOffset = computePayloadOffset(network, transport, this.data, this.size);

  /***************** public methods *****************/

  this.getPayloadOffset = function() {
	return this.payloadOffset;
  }

  this.hasData = function() {
	var ret = false;
	if(this.size > 0)
		ret = (this.size-this.payloadOffset) > 0;
	return ret;
  }

  this.toStr = function() {
	return ("size: " + this.size.toString()
			  + " has data: " + this.hasData().toString()
			  + " payload offset: " + this.payloadOffset.toString()
			  + " payload size: " + (this.size-this.payloadOffset).toString()
			 );
  }

  function computePayloadOffset(network, transport, buf, size) {
	var trHdrLen = 8; 	//UDP header is 8 bytes
	var nwHdrLen = 20;  //default IPv4 hdr, length 20 bytes
	var vlanFlagsLen = 0;

	if(network == 0xdd86) {  //IPv6
	  nwHdrLen = 40;		//IPV6 network layer header is 40 bytes
	}

	if (network == 0x81) {//VLAN (https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
	  vlanFlagsLen = 2;
	}
	if(size >= 65 && transport == 6) {	//TCP
	  trHdrLen = (((buf[62]>>4)&0xf) * 4);
	}

	return (
	  16  			 //tcpdump header: ts_sec, ts_usec, incl_len, orig_len
	  + 14 			 //link-layer header: srcMac 6, dstMac 6, nwHdrType 2 bytes
	  + vlanFlagsLen //vlan labels
	  + nwHdrLen 	 //network layer header
	  + trHdrLen    //transport layer header
	);
  }
}

/******************* public helper functions *****************/

function getByte(buf, pos) {
  //return buf.length > pos ? buf[pos]&0xff : 0;
  return buf[pos]&0xff;
}

function getBytes(buf, from, to) {
  var ret = [];
  //if(from > buf.length || to > buf.length || from < 0 || to < 0) return ret;
  for(var i=0; i+from<to; i++) {
	ret.push(buf[from+i]&0xff);
  }
  return ret;
}

function bytesToStr(byteArray, from, to) {
  var ret = [];
  //if(from > byteArray.length || to > byteArray.length || from < 0 || to < 0) return ret;
  for(var i=0; from+i<to; i++) {
	if(i%16==0) ret.push("\n");
	ret.push(pad((byteArray[from+i]&0xff).toString(16),2) + " ");
  }
  return ret.join("");
}

function getShort(buf, pos) {
  //return buf.length > pos+1 ? (((buf[pos]<<8)&0xff00) | (buf[pos+1]&0x00ff)) : 0;
  return (((buf[pos]<<8)&0xff00) | (buf[pos+1]&0x00ff));
}

function getInt(buf, pos) {
//  if(buf.length <= pos+3) return 0;
  return ( ((buf[pos]<<24)&0xff000000)
			 | ((buf[pos+1]<<16)&0xff0000)
			 | ((buf[pos+2]<<8)&0xff00)
			 | (buf[pos+3]&0xff)
			);
}

function getShortReverse(buf, pos) {
  //return buf.length > pos+1 ? (((buf[pos+1]<<8)&0xff00) | (buf[pos]&0x00ff)) : 0;
  return (((buf[pos+1]<<8)&0xff00) | (buf[pos]&0x00ff));
}

function getIntReverse(buf, pos) {
//  if(buf.length <= pos+3) return 0;
  return ( ((buf[pos+3]<<24)&0xff000000)
			 | ((buf[pos+2]<<16)&0xff0000)
			 | ((buf[pos+1]<<8)&0xff00)
			 | (buf[pos]&0xff)
			);
}

function pad(num, size) {
  var s = ""+num;
  while (s.length < size) s = "0" + s;
  return s;
}
