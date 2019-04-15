/*
*@Function: Spider2 js template
*@Author:   YuYingXia
*@Date:     2013-07-16
*@History:  2013-07-16 init
*           2013-07-18 Add onResourceRequested function to support ajax
*           2013-07-22 Add function tag to generate event trigger function
*           2013-07-24 Add function getLinksByLink to support link's href value
*                      Add links == null judge 
*           2013-07-25 Add form action tag
*           2013-07-29 Add frame and iframe function
*@Todo:     a.Modify it to be a real template
*           b.Add event trigger
*           c.iframe tag
*/

var links = [];
var url = '$URL';
var casper = require('casper').create({
    verbose: false,
    logLevel: "error",
    onResourceRequested:function(self, request){
	//links = links.concat([request.url]);
        this.echo(request.url);
    }
});

function getLinks() {
    var links = document.querySelectorAll('a');
    return Array.prototype.map.call(links, function(e) {
        return e.getAttribute('href')
    });
}

function getLinksByFrame() {
    var links = document.querySelectorAll('frame');
    return Array.prototype.map.call(links, function(e) {
        return e.getAttribute('src')
    });
}

function getLinksByIframe() {
    var links = document.querySelectorAll('iframe');
    return Array.prototype.map.call(links, function(e) {
        return e.getAttribute('src')
    });
}

function getLinksByLink() {
    var links = document.querySelectorAll('link');
    return Array.prototype.map.call(links, function(e) {
        r = e.getAttribute('href');
        return null == r ? url : r;
    });
}

function getLinksByForm(){
    var links = document.querySelectorAll('form');
    return Array.prototype.map.call(links, function(e) {
        return e.getAttribute('action')
    });
}

Array.prototype.unique = function(){
    var res = [];
    var json = {};
    for(var i = 0; i < this.length; i++){
        if(!json[this[i]]){
            res.push(this[i]);
            json[this[i]] = 1;
        }
    }
    return res;
}

casper.start(url, function() {
});

casper.then(function() {
    links = links.concat(this.evaluate(getLinks));
    links = links.concat(this.evaluate(getLinksByLink));
    links = links.concat(this.evaluate(getLinksByForm));
    links = links.concat(this.evaluate(getLinksByFrame));
    links = links.concat(this.evaluate(getLinksByIframe));
});

//$function


casper.run(function() {
    if(null == links){this.exit();}
    links = links.unique();
    this.echo(links.join('\n')).exit();
});

