#!/system/bin/sh
for pid in /proc/[0-9]*; do
  if [ -r "$pid/stat" ]; then
    stat=$(cat "$pid/stat" 2>/dev/null)
    if [ -n "$stat" ]; then
      # comm 是第2字段, 在括号中. utime是14, stime是15
      # 把括号内容换成下划线再切
      cleaned=$(echo "$stat" | sed 's/(.*//; s/.*)//')
      comm=$(echo "$stat" | sed 's/.*)\s*//; s/\(.*//')
      # 删除括号后用 awk
      nodename=$(echo "$stat" | awk -F'[()]' '{print $2}')
      rest=$(echo "$stat" | awk -F'[()]' '{print $3}')
      utime=$(echo "$rest" | awk '{print $12}')
      stime=$(echo "$rest" | awk '{print $13}')
      if [ -n "$utime" ] && [ -n "$stime" ]; then
        total=$((utime + stime))
        echo "$total $pid $nodename"
      fi
    fi
  fi
done | sort -rn | head -25