/* https://tools.ietf.org/html/rfc1035 section 4.1
   PCAP protocol dissector for DNS messages
   
   Extracts all message header fields (except Z), question and answer sections.
   Authority and additional sections are ignored.
   Extracts only IPv4, IPv6 and CNAME RDATA from answer section.
   
   Tested on newtork layer IPv4, IPv6 and transport layer UDP and TCP. (IPv6 + TCP not tested).
*/
var base;	 //start of dns message (pcap packet payload)
var offset;  //current position in the dns message
var limit;   //dns message size

function AnswerSection() {
  this.name = "";
  this.type = 0;
  this.class = 0;
  this.ttl = 0;
  this.rdata = "";

  this.toString = function() {
	return (
	  "\n\t\t" + "{" +
	  	"\n\t\t\t" + "name: " + this.name +
	  	"\n\t\t\t" + "type: " + this.type.toString() +
	  	"\n\t\t\t" + "class: " + this.class.toString() +
	  	"\n\t\t\t" + "ttl: " + this.ttl.toString() +
	  	"\n\t\t\t" + "rdata: " + this.rdata +
	  "\n\t\t" + "}"
	);
  }
}

function QuestionSection() {
  this.qName = "";
  this.qType = -1;
  this.qClass = -1;

  this.toString = function() {
	return (
	  "\n\t" + "{" +
	  	"\n\t\t" + "qType: " + this.qType.toString() +
	  	"\n\t\t" + "qClass: " + this.qClass.toString() +
	  	"\n\t\t" + "qName: " + this.qName +
	  "\n\t" + "}"
	);
  }
}


function parseDnsMessage(bytes, captureLen, networkType, transportType, srcPort, dstPort) {

  // PcapPcaket provides convenience methods for handling pcap packet
  var packet = new PcapPacket(bytes, captureLen, networkType, transportType);
  if(!packet.hasData() || (srcPort!=53 && dstPort!=53)){
	return null;
  }
  var buf = bytes;
  base = packet.getPayloadOffset();
  if(transportType == 6) //skip TCP payload len
  	base += 2;
  offset = base;
  limit = packet.size;

  if(limit >= offset+12) {
	var txId 			= getShort(buf, offset);  offset += 2;
	var flags 			= getShort(buf, offset);  offset += 2;
	var questionCnt 	= getShort(buf, offset);  offset += 2;
	var answerRRCnt 	= getShort(buf, offset);  offset += 2;
	var authorityRRCnt 	= getShort(buf, offset);  offset += 2;
	var additionalRRCnt = getShort(buf, offset);  offset += 2;
  }
  var opCode = (flags>>11)&0xf;

  var qArray = [];
  for(var i=0; i<questionCnt; i++) {
	var q = getQueries(buf);
	qArray.push(q);
  }

  var aArray = [];
  for(var i=0; i<answerRRCnt; i++) {
	var a = getAnswers(buf);
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
  var ret = new AnswerSection();
  ret.rdata = "";

  if((offset + 8) > limit) return ret;

  var p = (getShort(buf, offset)&0x3fff) + base; offset += 2;
  ret.name = getName(p, buf, 0);
  ret.type  = getShort(buf, offset); offset += 2;
  ret.class = getShort(buf, offset); offset += 2;
  ret.ttl 	= getInt(buf, offset); 	 offset += 4;
  var rdLen = getShort(buf, offset); offset += 2;

  if(offset + rdLen > limit) return ret;
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
	var slen = getByte(buf, offset); offset++;
	if(slen == 0) break;
	var label = [];
	for(var i=offset; i<offset+slen;i++) {
	  label.push(buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : '.');
	}
	question.push(label.join(""));
	offset += slen;
  }

  var ret = new QuestionSection();
  if(offset <= limit) {
	ret.qType  = getShort(buf, offset); offset += 2;
	ret.qClass = getShort(buf, offset); offset += 2;
  }
  ret.qName = question.join(".");

  return ret;
}

function getName(pos, buf, depth) {
  var ret = [];
  if(depth > 10) {
	return "Name contains pointer that loops";
  }
  while((pos < limit)) {
	var slen = getByte(buf, pos); pos++;
	var label = [];
	if(slen == 0) {
	  break;  // stop processing after last label
	} else if ((slen&0xc0)!=0) { //referred label in compressed message
	  var newPos = (((slen<<8)&0x3f00) | getByte(buf, pos)) + base;
	  if(newPos < limit) {
		var nDepth = depth + 1;
		ret.push(getName(newPos, buf, nDepth));
	  }
	  break;
	}
  	for(var i=pos; i<pos+slen && i<limit;i++) {
	  var b = getByte(buf, i);
	  label.push(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.');
	}
	ret.push(label.join(""));
	pos += slen;
  }
  return ret.join(".");
}

function getIpv4Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<(pos+len) && i<limit;i++) {
	ret.push(getByte(buf, i).toString());
  }
  return ret.join(".");
}

function getIpv6Str(pos, buf, len) {
  var ret = [];
  for(i=pos; i<(pos+len) && i<limit;i+=2) {
	ret.push(pad(getByte(buf,i).toString(16),2) + pad(getByte(buf,i+1).toString(16),2));
  }
  return ret.join(":");
}

