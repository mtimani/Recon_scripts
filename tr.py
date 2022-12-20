#!/usr/bin/python3


#----------------Imports----------------#
import pandas as pd
import ta
import json
import sys
import argparse
import os
import os.path
import concurrent.futures
import numpy as np
from pygments import highlight
from collections import Counter 
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer
from termcolor import colored, cprint
from backtesting import Backtest, Strategy
from backtesting.lib import crossover
from binance import Client
from binance.exceptions import BinanceAPIException



#-------Initialize binance Client-------#
client = Client()



#----------------Cryptos----------------#
coins = ["ETHUSDT"]
coins = ["AAVEUSDT","ABBCUSDT","ADAUSDT","ALGOUSDT","AMPUSDT","ANKRUSDT","ANTUSDT","APEUSDT","APIUSDT","APTUSDT","ARUSDT","ASTRUSDT","ATOMUSDT","AUDIOUSDT","AVAXUSDT","AXSUSDT","BALUSDT","BATUSDT","BCHUSDT","BITUSDT","BNBUSDT","BNXUSDT","BONEUSDT","BORAUSDT","BSVUSDT","BTCUSDT","BTGUSDT","BTRSTUSDT","BTTUSDT","BUSDUSDT","CAKEUSDT","CELUSDT","CELOUSDT","CELRUSDT","CHRUSDT","CHSBUSDT","CHZUSDT","COMPUSDT","CROUSDT","CRVUSDT","CSPRUSDT","CVCUSDT","CVXUSDT","DAIUSDT","DAOUSDT","DASHUSDT","DCRUSDT","DGBUSDT","DOGEUSDT","DOTUSDT","DYDXUSDT","EGLDUSDT","ELONUSDT","ENJUSDT","ENSUSDT","EOSUSDT","ETCUSDT","ETHUSDT","ETHWUSDT","EWTUSDT","FEIUSDT","FILUSDT","FLOWUSDT","FLUXUSDT","FTMUSDT","FXSUSDT","GALAUSDT","GLMUSDT","GLMRUSDT","GMTUSDT","GMXUSDT","GNOUSDT","GRTUSDT","GTUSDT","GUSDUSDT","HBARUSDT","HIVEUSDT","HNTUSDT","HOTUSDT","HTUSDT","ICPUSDT","ICXUSDT","ILVUSDT","IMXUSDT","INJUSDT","IOSTUSDT","IOTXUSDT","JASMYUSDT","JSTUSDT","KAVAUSDT","KCSUSDT","KDAUSDT","KLAYUSDT","KNCUSDT","KSMUSDT","LDOUSDT","LEOUSDT","LINKUSDT","LPTUSDT","LRCUSDT","LSKUSDT","LTCUSDT","LUNAUSDT","LUNCUSDT","MAGICUSDT","MANAUSDT","MASKUSDT","MATICUSDT","MDXUSDT","MEDUSDT","METISUSDT","MINAUSDT","MIOTAUSDT","MKRUSDT","MXUSDT","MXCUSDT","NEARUSDT","NEOUSDT","NEXOUSDT","NFTUSDT","OCEANUSDT","OKBUSDT","OMGUSDT","ONEUSDT","ONGUSDT","ONTUSDT","OPUSDT","OSMOUSDT","PAXGUSDT","PEOPLEUSDT","PLAUSDT","POLYUSDT","PUNDIXUSDT","PYRUSDT","QNTUSDT","QTUMUSDT","RBNUSDT","REQUSDT","RLCUSDT","RNDRUSDT","ROSEUSDT","RSRUSDT","RUNEUSDT","RVNUSDT","SANDUSDT","SCUSDT","SCRTUSDT","SFPUSDT","SHIBUSDT","SKLUSDT","SLPUSDT","SNTUSDT","SNXUSDT","SOLUSDT","SSVUSDT","STORJUSDT","STXUSDT","SUSHIUSDT","SXPUSDT","SYSUSDT","TUSDT","TFUELUSDT","THETAUSDT","TONUSDT","TRIBEUSDT","TRXUSDT","TUSDUSDT","TWTUSDT","UMAUSDT","UNIUSDT","USDCUSDT","USDDUSDT","USDNUSDT","USDPUSDT","USDTUSDT","USTCUSDT","VETUSDT","VGXUSDT","WAVESUSDT","WAXPUSDT","WBTCUSDT","WINUSDT","WOOUSDT","XCHUSDT","XCNUSDT","XDCUSDT","XECUSDT","XEMUSDT","XLMUSDT","XMRUSDT","XNOUSDT","XRPUSDT","XTZUSDT","XYMUSDT","YFIUSDT","ZECUSDT","ZENUSDT","ZILUSDT","ZRXUSDT"]


#-----------Global variables------------#
sl_p = 0
tp_p = 0
strategy = 0
exceptional = []



#---------Get data from Binance---------#
def getData(symbol, start):
    frame = pd.DataFrame(client.get_historical_klines(symbol, '4h', start))
    frame = frame[[0,1,2,3,4]]
    frame.columns = ['Date','Open','High','Low','Close']
    frame.Date = pd.to_datetime(frame.Date, unit='ms')
    frame.set_index('Date', inplace=True)
    frame = frame.astype(float)
    return frame



#-------------Trading class-------------#
class DataTrader(Strategy):

    def init(self):
        close = self.data.Close
        self.macd = self.I(ta.trend.macd, pd.Series(close))
        self.macd_signal = self.I(ta.trend.macd_signal, pd.Series(close))
        self.ema_50 = self.I(ta.trend.ema_indicator, pd.Series(close), window=100)
        self.ema_50 = self.I(ta.trend.ema_indicator, pd.Series(close), window=50)
        self.ema_20  = self.I(ta.trend.ema_indicator, pd.Series(close), window=20)
        global sl_p
        global tp_p
        global strategy
        self.sl_p = sl_p
        self.tp_p = tp_p
        self.strat = strategy

    def next(self):
        price = self.data.Close

        sl = price * self.sl_p
        tp = price * self.tp_p

        if self.strat == "1":
            if crossover(self.macd, self.macd_signal) and price < self.ema_100:
                self.buy(sl = sl, tp = tp)
            elif crossover(self.macd, self.macd_signal) and price > self.ema_100:
                self.sell(sl = tp, tp = sl)
        elif self.strat == "2":
            if crossover(self.macd, self.macd_signal) and price < self.ema_50:
                self.buy(sl = sl, tp = tp)
            elif crossover(self.macd, self.macd_signal) and price > self.ema_50:
                self.sell(sl = tp, tp = sl)
        elif self.strat == "3":
            if crossover(self.macd, self.macd_signal) and price > self.ema_20 and self.ema_20 > self.ema_50:
                self.buy(sl = sl, tp = tp)
            elif crossover(self.macd, self.macd_signal) and price < self.ema_20 and self.ema_20 < self.ema_50:
                self.sell(sl = tp, tp = sl)



#--Worker running different strategies--#
def worker_f(directory, loss, strat, logging):
    ## Variable initialization
    results = {}

    global sl_p
    global tp_p
    global strategy

    sl_p = 1 - loss
    tp_p = 1 + 3 * loss
    strategy = strat

    for coin in coins:
        try:
            df = getData(coin, '2022-01-01')
            bt = Backtest(df, DataTrader, cash = 100000, commission = 0.0015)
            output = bt.run()
            results[coin] = output['Return [%]']
            ## Exceptional calculation
            if output['Return [%]'] > 100:
                exceptional.append({"sl": sl_p, "tp": tp_p, "coin": coin, "average": output['Return [%]']})
        except BinanceAPIException as e:
            if logging:
                cprint('Coin ' + coin + ' is not available', 'blue')
            continue
        except:
            if logging:
                cprint('An error occured for ' + coin, 'red')
            continue

    ## Average calculation
    average = 0
    for val in results.values():
        average += val
    average = average / len(results)

    ## Final json formatting
    final = {"sl": sl_p, "tp": tp_p, "average": average, "results": results}
    formatted_final = json.dumps(final, indent=4)
    
    if logging:
        colorful = highlight(formatted_final, lexer=JsonLexer(), formatter=Terminal256Formatter())
        print(colorful)

    ## Write into output directory
    output_dir = directory + "/Strategy_" + strategy + "_statistics/"
    output_file = output_dir + "sl_" + str(sl_p) + "_tp_" + str(tp_p) + ".json"
    print(output_file)
    with open(output_file, "w") as fp:
        fp.write(formatted_final)



#------Validate Strategy Parameter------#
class validateStrategyParameter(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values != "1" and values != "2" and values != "3":
            parser.error(f"Please enter a valid strategy number (1, 2 or 3). Got: {values}")
        setattr(namespace, self.dest, values)
    


#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')

    ## Arguments
    parser.add_argument("-l", "--logging", action='store_true', dest="logging", help="enable logging in the console")
    parser.add_argument("-s", "--strategy", dest="strategy", help="choose strategy between 1, 2 or 3", required=False, default=1, action=validateStrategyParameter)
    required.add_argument("-d", "--directory", dest="directory", help="directory that will store results", required=True)
    return parser



#-------------Main Function-------------#
def main(args):
    ## Variables
    directory   = args.directory
    logging     = args.logging
    strategy    = args.strategy

    ## Create output directories
    try:
        os.mkdir(directory + "/Strategy_" + strategy + "_statistics")
        cprint("Creation of " + directory + "/Strategy_" + strategy + "_statistics directory", 'blue')
    except FileExistsError:
        cprint("Directory " + directory + "/Strategy_" + strategy + "_statistics already exists", 'blue')
    except:
        raise

    ## Multithread
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_f = {executor.submit(worker_f, directory, loss, strategy, logging): loss for loss in np.arange(0.01,0.1,0.01)}

        for future in concurrent.futures.as_completed(future_f):
            None

    ## Write exceptional to file
    output_file = directory + "/Strategy_" + strategy + "_statistics/exceptional.json"
    with open(output_file, "w") as fp:
        fp.write(json.dumps(exceptional, indent=4))

    ## Add Counter functionality

    



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
