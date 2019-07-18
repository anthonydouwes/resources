/* https://tools.ietf.org/html/rfc1035 section 4.1
   PCAP protocol dissector for DNS messages
   
   Extracts all message header fields (except Z), question and answer sections.
   Authority and additional sections are ignored.
   
   Works on IPv4, IPv6, UDP and TCP. (TCP on IPv6 not tested).
*/
var base;    //dns section position
var offset;  //current position in the dns block 
var limit;   //total pcap block size

function dissectDnsMessage(bytes) {
  var hasData = processHdr(bytes);
  
  if(!hasData){
	return {txId:-1, 
			flags:-1,
			opCode:-1,
			isQuery:false,
			isAuthoritative:false,
			isTruncated:false,
			recursionDesired:false,
			recursionAvailable:false,
			rCode:-1,
			questionCnt:-1,
			answerCnt:-1, 
			authorityCnt:-1, 
			additionalCnt:-1,
			queries:[],
			answers:[]
		   };	
  }
  
  var txId = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  var flags = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  var questionCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  var answerRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  var authorityRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;
  var additionalRRCnt = (((bytes[offset]<<8)&0xff00) | bytes[offset+1]&0x00ff); offset += 2;

  var opCode = (flags>>11)&0xf;

  var qArray = [];
  for(var i=0; i<questionCnt; i++) {
	var q = getQueries(bytes);
	qArray.push(q);
  }
  
  var aArray = [];
  for(var i=0; i<answerRRCnt; i++) {
	var a = getAnswers(bytes);
	aArray.push(a);
  }
  
  return {txId:txId, 
		  flags:flags,
		  opCode:opCode,
		  isQuery:(flags&0x8000)==0,
		  isAuthoritative:(flags&0x400)!=0,
		  isTruncated:(flags&0x200)!=0,
		  recursionDesired:(flags&0x100)!=0,
		  recursionAvailable:(flags&0x80)!=0,
		  rCode:(flags&0xf),
		  questionCnt:questionCnt, 
		  answerCnt:answerRRCnt, 
		  authorityCnt:authorityRRCnt, 
		  additionalCnt:additionalRRCnt,
		  queries:qArray,
		  answers:aArray
		 };
}

function getAnswers(buf) {
  var ret = new Object();
  var p = (((buf[offset]<<8)&0x3f00) | buf[offset+1]&0x00ff) + base; offset += 2;
  ret.name = getName(p, buf, 0);

  ret.type = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.class = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.ttl = ( ((buf[offset]<<24)&0xff000000)
			 | ((buf[offset+1]<<16)&0xff0000)
			 | ((buf[offset+2]<<8)&0xff00)
			 | (buf[offset+3]&0xff)
			); offset += 4;
  var rdLen = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.address = "";

  if(ret.type == 1) //IPv4
	ret.rdata = getIpv4Str(offset, buf, rdLen);
  else if(ret.type == 5) //CNAME
  	ret.rdata = getName(offset, buf);
  else if(ret.type == 28) //IPv6
	ret.rdata = getIpv6Str(offset, buf, rdLen);

  offset += rdLen;
  return ret;
}

function getQueries(buf) {
  var question = [];
  while(offset < limit) {
	var slen = buf[offset]&0xff; offset++;
	if(slen == 0) break;
	var label = [];
	for(var i=offset; i<offset+slen;i++) {
	  label.push(buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : '.');
	}
	question.push(label.join(""));
	offset += slen;
  }
  var ret = new Object();

  ret.qType = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.qClass = (((buf[offset]<<8)&0xff00) | buf[offset+1]&0x00ff); offset += 2;
  ret.qName = question.join(".");

  return ret;
}

function getName(pos, buf, depth) {
  var question = [];
  if(depth > 10) {
	return "Name contains pointer that loops";
  }
  while((pos < limit)) {
	var slen = (buf[(pos)]&0xff); pos++;
	var label = [];
	if(slen == 0) {
	  break;  // stop processing after last label
	  } else if ((slen&0xc0)!=0) { //referred label
		newPos = (((slen<<8)&0x3f00) | buf[pos]&0x00ff) + base;
		var nDepth = depth + 1;
		question.push(getName(newPos, buf, nDepth));
	  break;
	}
  	for(var i=pos; i<pos+slen;i++) {
	  label.push(buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : '.');
	}
	question.push(label.join(""));
	pos += slen;
  }
  return question.join(".");
}

function getIpv4Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<pos+len;i++) {
	ret.push((buf[i]&0xff).toString());
  }
  return ret.join(".");
}

function getIpv6Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<pos+len;i+=2) {
	ret.push( pad((buf[i]&0xff).toString(16),2) + pad((buf[i+1]&0xff).toString(16),2));
  }
  return ret.join(":");
}

function pad(num, size) {
  var s = ""+num;
  while (s.length < size) s = "0" + s;
  return s;
}

/* computes payload offset in buf
   returns true if payload exists.
*/
function processHdr(buf) {
  var ethFrameType = (((buf[28]<<8)&0xff00) | buf[29]&0x00ff);

  var ipHdrLen = 20;
  var ipProto = 17;		//UDP
  var vlanHdrLen = 0;
  var ipProtoHdrLen = 8 //UDP header is 8 bytes


  if(ethFrameType == 0x86dd) { //IPv6
	ipHdrLen = 40;
	ipProto = buf[36]&0xff;
  } else if (ethFrameType == 0x800) {  //IPv4
	ipProto = buf[39]&0xff;
  }

  if (ethFrameType == 8100) {//VLAN
	vlanHdrLen = 4;
  }


  if(ipProto == 6) {	//TCP
	ipProtoHdrLen = (((buf[62]>>4)&0xf) * 4) + 2;
  }

  base = 16  		//ts_sec, ts_usec, incl_len, orig_len
    + 12 			//srcMac, dstMac
    + 2 			//ethFrameType
    + vlanHdrLen	//vlan labels
	+ ipHdrLen 		//IPV6 ip header is 40 bytes, IPV4 header is 20 bytes
    + ipProtoHdrLen	//UDP header is 8 bytes
  ;
  offset = base;
  limit = buf.length;

  var ret = true;
  if(ipProto == 6) {
	ret = (buf[63]&0x08) != 0  //when ip proto is TCP return true only if PUSH tcp flag set
  }

  return ret;
}
