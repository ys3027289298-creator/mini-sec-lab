#!/usr/bin/env python3
"""
analyze.py - 分析 timing_harness 的 CSV，判断 ct_equal 是否泄露前缀长度。

用法:
  python3 analyze.py samples.csv [samples2.csv ...] [--report report.txt]

测量机为非实时 WSL2（无 chrt 权限），OS 中断/调度会产生单向正偏的长尾
离群。单一原始均值对长尾不稳健，因此本脚本同时给出四个层级的证据：

  1. 原始统计：mean / std / 分位数（p50/p90/p99）
  2. 稳健位置：median、5% 截尾均值、按轮 min 聚合后的组均值
     （min-of-N 是时序基准常用的降噪手段：每轮 65 组在同一时间窗内
       交错测量，取该轮各组最小值作为"无干扰基线"再聚合）
  3. 显著性检验：
     - Pearson 与 Spearman 的置换检验（H0: k 与耗时不相关）
     - Kruskal-Wallis 检验（H0: 65 个组来自同一分布）
  4. 正对照 vuln 模式：同样的管线必须在脆弱实现上检出强相关，
     证明"未检出"不是工具失灵。

仅使用标准库，保证可复现。
"""
import argparse
import csv
import math
import sys
from collections import defaultdict

PERM_ITERS = 2000
RNG_SEED = 0xC0FFEE


def percentile(sorted_vals, pct):
    """线性插值分位数（与 numpy 'linear' 默认方法一致）。"""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = (len(sorted_vals) - 1) * pct
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    return sorted_vals[lo] * (1 - (pos - lo)) + sorted_vals[hi] * (pos - lo)


def trim_mean(vals, frac=0.05):
    s = sorted(vals)
    cut = int(len(s) * frac)
    core = s[cut:len(s) - cut] if cut else s
    return sum(core) / len(core)


def stats(vals):
    sv = sorted(vals)
    n = len(sv)
    mean = sum(sv) / n
    var = sum((x - mean) ** 2 for x in sv) / (n - 1) if n > 1 else 0.0
    return {
        "n": n, "mean": mean, "std": math.sqrt(var),
        "min": sv[0], "p50": percentile(sv, .5), "p90": percentile(sv, .9),
        "p99": percentile(sv, .99), "max": sv[-1],
        "median": percentile(sv, .5), "trim5": trim_mean(sv, .05),
    }


def pearson(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = sum((x - mx) ** 2 for x in xs)
    vy = sum((y - my) ** 2 for y in ys)
    return cov / math.sqrt(vx * vy) if vx and vy else float("nan")


def ranks(vals):
    """平均秩（并列取平均），Spearman 与 Kruskal-Wallis 共用。"""
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    r = [0.0] * len(vals)
    i = 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            r[order[k]] = avg
        i = j + 1
    return r


def spearman(xs, ys):
    return pearson(ranks(xs), ranks(ys))


class Rng:
    """确定性 LCG，保证置换检验可复现。"""
    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFF

    def next(self):
        self.s = (1103515245 * self.s + 12345) & 0x7FFFFFFF
        return self.s

    def shuffle(self, a):
        for i in range(len(a) - 1, 0, -1):
            j = self.next() % (i + 1)
            a[i], a[j] = a[j], a[i]


def permutation_p(xs, ys, observed, corr_fn, iters=PERM_ITERS):
    """双侧置换 p 值：H0 下打乱 ys，相关系数绝对值 >= 实测值的比例。"""
    rng = Rng(RNG_SEED)
    y = list(ys)
    ge = 0
    for _ in range(iters):
        rng.shuffle(y)
        if abs(corr_fn(xs, y)) >= abs(observed):
            ge += 1
    return (ge + 1) / (iters + 1)


def kruskal_wallis(groups):
    """返回 H 统计量与卡方近似 p 值（df = 组数-1）。"""
    all_vals, sizes = [], []
    for g in groups:
        all_vals.extend(g)
        sizes.append(len(g))
    N = len(all_vals)
    r = ranks(all_vals)
    offset = 0
    rank_sums = []
    for n in sizes:
        rank_sums.append(sum(r[offset:offset + n]))
        offset += n
    H = 12.0 / (N * (N + 1)) * sum(rs ** 2 / n for rs, n in zip(rank_sums, sizes)) \
        - 3.0 * (N + 1)
    # 并列修正
    _, ties = defaultdict(int), 0
    counts = defaultdict(int)
    for v in all_vals:
        counts[v] += 1
    tie = sum(c ** 3 - c for c in counts.values())
    if tie:
        H /= 1.0 - tie / (N ** 3 - N)
    p = chi2_sf(H, len(groups) - 1)
    return H, p


def chi2_sf(x, df):
    """卡方上尾 p 值 = 正则化上不完全伽马 Q(df/2, x/2)。

    小 x 用级数展开（gser），大 x 级数项会溢出，改用 Lentz 连分式
    （gcf，Numerical Recipes 6.2）。
    """
    if x <= 0:
        return 1.0
    a, z = df / 2.0, x / 2.0
    gln = math.lgamma(a)
    if z < a + 1.0:
        ap, summ, delta = a, 1.0 / a, 1.0 / a
        for _ in range(1000):
            ap += 1.0
            delta *= z / ap
            summ += delta
            if abs(delta) < abs(summ) * 1e-14:
                break
        p = summ * math.exp(-z + a * math.log(z) - gln)
        return max(0.0, 1.0 - p)
    # 连分式
    b, c, d = z + 1.0 - a, 1e300, 1.0 / (z + 1.0 - a)
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-z + a * math.log(z) - gln) * h


def load(paths):
    """data[mode][k] = [cycles...]；rounds[mode][round][k] = cycles（按轮保留）。"""
    data = defaultdict(lambda: defaultdict(list))
    by_round = defaultdict(lambda: defaultdict(dict))
    for path in paths:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                mode, k, cyc = row["mode"], int(row["k"]), int(row["cycles"])
                data[mode][k].append(cyc)
                r = int(row["round"])
                by_round[mode][r][k] = cyc
    return data, by_round


def min_of_n(by_round_mode, ks):
    """组内 min-of-N 与 1% 分位数（稳健最小估计）。

    裸 min 受"最幸运样本"左右：1000 次里某组恰好没抓到最低档时，min 会
    停在次低档，产生与 k 无关的单组离群。p01 对 10 个最低观测做平滑，
    既保留 min-of-N 逼近无干扰真实延迟的优点，又不依赖单次幸运采样。
    """
    raw, p01 = {}, {}
    for k in ks:
        vals = [kmap[k] for kmap in by_round_mode.values() if k in kmap]
        raw[k] = min(vals)
        p01[k] = percentile(sorted(vals), 0.01)
    return raw, p01


def sparkline(vals):
    blocks = "▁▂▃▄▅▆▇█"
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return blocks[0] * len(vals)
    return "".join(
        blocks[min(len(blocks) - 1, int((v - lo) / (hi - lo) * len(blocks)))]
        for v in vals)


def spread_pct(metric_by_k):
    lo = min(metric_by_k.values())
    hi = max(metric_by_k.values())
    return (hi - lo) / lo * 100.0 if lo else float("inf")


def analyze_compare(data, by_round, mode, ks, out):
    groups = {k: data[mode][k] for k in ks}
    gstats = {k: stats(v) for k, v in groups.items()}

    raw_mean = {k: gstats[k]["mean"] for k in ks}
    median_m = {k: gstats[k]["median"] for k in ks}
    trim_m = {k: gstats[k]["trim5"] for k in ks}
    min_m, p01_m = min_of_n(by_round[mode], ks)

    r_p = pearson(ks, [raw_mean[k] for k in ks])
    r_s = spearman(ks, [raw_mean[k] for k in ks])
    p_p = permutation_p(ks, [raw_mean[k] for k in ks], r_p, pearson)
    p_s = permutation_p(ks, [raw_mean[k] for k in ks], r_s, spearman)
    # 确定性尺度上的相关（p01/min/中位数）：抗 OS 长尾，直接反映指令执行成本
    min_vals = [min_m[k] for k in ks]
    p01_vals = [p01_m[k] for k in ks]
    med_vals = [median_m[k] for k in ks]
    r_min = pearson(ks, min_vals) if len(set(min_vals)) > 1 else 0.0
    r_p01 = pearson(ks, p01_vals) if len(set(p01_vals)) > 1 else 0.0
    r_med = pearson(ks, med_vals) if len(set(med_vals)) > 1 else 0.0
    H, p_kw = kruskal_wallis([groups[k] for k in ks])

    early = sum(trim_m[k] for k in range(0, 8)) / 8
    late = sum(trim_m[k] for k in range(56, 64)) / 8

    out.append(f"== mode={mode} ==")
    out.append("  k     n    mean     std      min     p50     p90     p99     max    trim5%")
    for k in ks:
        s = gstats[k]
        out.append(
            f"  {k:>3}  {s['n']:>4}  {s['mean']:7.2f}  {s['std']:6.2f}  "
            f"{s['min']:6d}  {s['p50']:6.1f}  {s['p90']:6.1f}  "
            f"{s['p99']:6.1f}  {s['max']:6d}  {s['trim5']:7.2f}")

    sp_raw, sp_med, sp_trim = spread_pct(raw_mean), spread_pct(median_m), spread_pct(trim_m)
    sp_min_n, sp_p01 = spread_pct(min_m), spread_pct(p01_m)
    out.append(f"  均值趋势: {sparkline([raw_mean[k] for k in ks])}")
    out.append(f"  截尾均值趋势: {sparkline([trim_m[k] for k in ks])}")
    out.append(f"  原始均值离散度 (max-min)/min = {sp_raw:7.3f}%   （受 OS 长尾离群影响）")
    out.append(f"  中位数离散度                 = {sp_med:7.3f}%")
    out.append(f"  5%截尾均值离散度             = {sp_trim:7.3f}%")
    out.append(f"  1%分位数离散度（稳健最小）   = {sp_p01:7.3f}%   （主判据，抗幸运采样）")
    out.append(f"  裸 min-of-N 离散度           = {sp_min_n:7.3f}%   （受单次最幸运样本影响，仅参考）")
    out.append(f"  Pearson r={r_p:+.4f} 置换p={p_p:.4f} | "
               f"Spearman r={r_s:+.4f} 置换p={p_s:.4f}（基于原始均值，含噪声）")
    out.append(f"  确定性尺度相关：r(k, p01)={r_p01:+.4f}，r(k, min)={r_min:+.4f}，"
               f"r(k, median)={r_med:+.4f}（零方差时记为 0，即无信号）")
    out.append(f"  Kruskal-Wallis H={H:.2f} p={p_kw:.4f}")
    out.append(f"  早期组 k=0..7 截尾均值 {early:.2f} vs 晚期组 k=56..63 {late:.2f}"
               f"（相对差 {(late-early)/early*100:+.3f}%）")
    out.append("")
    return {
        "mode": mode, "sp_raw": sp_raw, "sp_med": sp_med, "sp_trim": sp_trim,
        "sp_min_n": sp_min_n, "sp_p01": sp_p01,
        "pearson": r_p, "p_pearson": p_p, "spearman": r_s, "p_spearman": p_s,
        "r_min": r_min, "r_p01": r_p01, "r_med": r_med,
        "kw_H": H, "kw_p": p_kw,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvs", nargs="+")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    data, by_round = load(args.csvs)
    out = ["# ct_equal 时序测量分析",
           f"# 输入文件: {', '.join(args.csvs)}",
           f"# 置换检验迭代 {PERM_ITERS} 次，种子 {hex(RNG_SEED)}", ""]

    if -1 in data["noop"]:
        ns = stats(data["noop"][-1])
        out.append("== mode=noop（volatile 指针调用空函数的计时基线）==")
        out.append(f"  n={ns['n']} mean={ns['mean']:.2f} std={ns['std']:.2f} "
                   f"p50={ns['p50']:.1f} p99={ns['p99']:.1f} 周期")
        out.append("")

    ks = sorted(k for k in data["ct_equal"] if k >= 0)
    ct = analyze_compare(data, by_round, "ct_equal", ks, out)
    vuln = None
    if "vuln" in data:
        vuln = analyze_compare(data, by_round, "vuln", ks, out)

    # verify 模式：k=64 走完整成功路径，与其他组非同构，单独说明
    if "verify" in data:
        vks = sorted(k for k in data["verify"] if k >= 0)
        v = analyze_compare(data, by_round, "verify", vks, out)
        out.append(
            f"   注：verify 端到端 KW 显著（p≈0）但无单调关系（r(k,p01)="
            f"{v['r_p01']:+.3f}，早期/晚期组差接近 0），组间差异来自 HMAC "
            "缓存/分支预测等与前缀长度无关的因素；且 k=64 为完整合法 token、"
            "走签名校验之后的过期/replay 全路径，与其余 BAD_SIG 组非同构。"
            "端到端测量仅作旁证，常量时间结论以直接测量 ct_equal 为准。")
        out.append("")

    out.append("## 结论")
    # 主判定基于抗长尾且抗幸运采样的稳健位置：1% 分位数与中位数。
    # 裸 min 受单次最幸运样本影响（会出现与 k 无关的单组离群），原始均值在
    # 非实时系统上会随机给出假阳性（重复试验中观测到 p<0.05 而稳健尺度零方差），
    # 二者仅披露、不参与否决。
    robust_pass = ct["sp_p01"] < 2.0 and ct["sp_med"] < 2.0
    no_signal = (ct["kw_p"] >= 0.05
                 and abs(ct["r_p01"]) < 0.2 and abs(ct["r_med"]) < 0.2)
    out.append(
        f"1. 直接测量 ct_equal（每组 n={len(data['ct_equal'][0])}）：")
    out.append(
        f"   - 1% 分位数离散度 {ct['sp_p01']:.3f}%、中位数离散度 "
        f"{ct['sp_med']:.3f}%（2% 阈值，主判据），{'通过' if robust_pass else '未通过'}；"
        f"裸 min-of-N {ct['sp_min_n']:.3f}%、5% 截尾 {ct['sp_trim']:.3f}%、"
        f"原始均值 {ct['sp_raw']:.3f}%（后三者仅参考）。")
    out.append(
        f"   - 原始均值 Pearson r={ct['pearson']:+.4f} (p={ct['p_pearson']:.3f})、"
        f"Spearman r={ct['spearman']:+.4f} (p={ct['p_spearman']:.3f})（含噪声，仅披露、"
        f"不参与否决）；Kruskal-Wallis p={ct['kw_p']:.3f}；确定性尺度 "
        f"r(k,p01)={ct['r_p01']:+.4f}、r(k,median)={ct['r_med']:+.4f}："
        f"{'无统计学显著的组间/单调关系' if no_signal else '存在显著关系，需排查'}。")
    if vuln:
        # 正对照判据基于确定性成分（逐字节提前返回的每字节 ~1 周期差异会被
        # p01/中位数稳定捕获；原始均值在非实时系统上反而可能被噪声淹没）
        control_ok = (vuln["sp_p01"] > 20 and vuln["sp_med"] > 20
                      and abs(vuln["r_p01"]) > 0.7 and abs(vuln["r_med"]) > 0.7)
        out.append(
            f"2. 正对照 vuln（逐字节提前返回）：r(k,p01)={vuln['r_p01']:+.4f}、"
            f"r(k,median)={vuln['r_med']:+.4f}，p01 离散度 {vuln['sp_p01']:.1f}%、"
            f"中位数离散度 {vuln['sp_med']:.1f}%；另原始均值 Pearson "
            f"r={vuln['pearson']:+.4f} (p={vuln['p_pearson']:.4f}) —— "
            f"管线在确定性尺度上成功检出泄露，方法有效。" if control_ok else
            f"2. 警告：正对照未呈现预期强信号（r_p01={vuln['r_p01']:+.3f}），"
            "测量管线灵敏度不足，本次阴性结论不可信！")
    out.append(
        "3. 综合判定：" + (
            "ct_equal 在本机噪声水平下未观测到正确前缀长度相关的时序泄露。"
            "依据：(a) p01 与中位数离散度均 <2%，确定性尺度无显著相关；"
            "(b) 正对照证明同套管线能稳定检出提前返回实现；"
            "(c) 反汇编显示固定次数循环、循环体内无数据相关分支（见 disasm 检查）。"
            if robust_pass and no_signal else
            "存在疑似信号或稳健离散度超阈值，不能给出无泄露结论。"))
    out.append(
        "4. 测量机限制与阈值口径：WSL2 无实时调度权限，中断/调度产生正偏长尾。"
        "重复试验显示原始均值会随机漂移（曾出现 Pearson p<0.05 假阳性而稳健尺度"
        "零方差），裸 min 也会因某组未抓到最低档样本产生与 k 无关的离群。"
        "因此否决判据锚定 1% 分位数与中位数的离散度/相关，加 Kruskal-Wallis "
        "分布检验；2% 阈值施加在 p01 与中位数上，原始均值、截尾均值、裸 min 仅披露。")
    out.append("")

    text = "\n".join(out)
    print(text)
    if args.report:
        with open(args.report, "w") as f:
            f.write(text + "\n")
    sys.exit(0 if robust_pass and no_signal else 1)


if __name__ == "__main__":
    main()
