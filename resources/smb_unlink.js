var filepath = "~~FILEPATH~~"
for(var i in extrafunc) {
  try {
    if(extrafunc[i].split("\n")[0].split(" ")[3] == '"' + filepath + '"') {
      extrafunc.splice(i-1, 1) // get rid of current item
    }
  }
  catch (e) { }
}
