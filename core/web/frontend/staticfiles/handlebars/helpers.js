Handlebars.registerHelper('equal', function(lvalue, rvalue, options) {
    if (arguments.length < 3)
        throw new Error("Handlebars Helper equal needs 2 parameters");
    if( lvalue!=rvalue ) {
        return options.inverse(this);
    } else {
        return options.fn(this);
    }
});

Handlebars.registerHelper("date", function(datetime) {
  var date = new Date(datetime);

  var month = date.getUTCMonth() + 1;
  if (month < 10) {
    month = "0" + month;
  }

  var day = date.getUTCDate();
  if (day < 10) {
    day = "0" + day;
  }

  return date.getUTCFullYear() + "-" + month + "-" + day;
});

Handlebars.registerHelper("datetime", function(datetime) {
  var date = new Date(datetime);

  var month = date.getUTCMonth() + 1;
  if (month < 10) {
    month = "0" + month;
  }

  var day = date.getUTCDate();
  if (day < 10) {
    day = "0" + day;
  }

  return date.getUTCFullYear() + "-" + month + "-" + day + " " + date.getUTCHours() + ":" + date.getUTCMinutes();
});

Handlebars.registerHelper("hasMoreHistory", function(link, options) {
  if ((link.history) && ((link.active) || (link.history.length > 1))) {
    return options.fn(this);
  } else {
    return options.inverse(this);
  }
});

Handlebars.registerHelper("isNotEmpty", function(links, options) {
  if (Object.keys(links).length > 0) {
    return options.fn(this);
  } else {
    return options.inverse(this);
  }
});

Handlebars.registerHelper("isInterestingNode", function (link, options) {
  if ((!link.visible) && (Object.keys(link.links_of_interest).length >= 2)) {
    return options.fn(this);
  } else {
    return options.inverse(this);
  }
});

Handlebars.registerHelper("dictLength", function(dict) {
  return Object.keys(dict).length;
});

Handlebars.registerHelper('join', function(val, delimiter) {
    var arry = [].concat(val);
    delimiter = ( typeof delimiter == "string" ? delimiter : ',' );
    return arry.join(delimiter);
});
