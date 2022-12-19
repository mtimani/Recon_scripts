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
coins = ["AAVEUSDT","ABBCUSDT","ADAUSDT","ALGOUSDT","AMPUSDT","ANKRUSDT","ANTUSDT","APEUSDT","APIUSDT","APTUSDT","ARUSDT","ASTRUSDT","ATOMUSDT","AUDIOUSDT","AVAXUSDT","AXSUSDT","BALUSDT","BATUSDT","BCHUSDT","BITUSDT","BNBUSDT","BNXUSDT","BONEUSDT","BORAUSDT","BSVUSDT","BTCUSDT","BTGUSDT","BTRSTUSDT","BTTUSDT","BUSDUSDT","CAKEUSDT","CELUSDT","CELOUSDT","CELRUSDT","CHRUSDT","CHSBUSDT","CHZUSDT","COMPUSDT","CROUSDT","CRVUSDT","CSPRUSDT","CVCUSDT","CVXUSDT","DAIUSDT","DAOUSDT","DASHUSDT","DCRUSDT","DGBUSDT","DOGEUSDT","DOTUSDT","DYDXUSDT","EGLDUSDT","ELONUSDT","ENJUSDT","ENSUSDT","EOSUSDT","ETCUSDT","ETHUSDT","ETHWUSDT","EWTUSDT","FEIUSDT","FILUSDT","FLOWUSDT","FLUXUSDT","FTMUSDT","FXSUSDT","GALAUSDT","GLMUSDT","GLMRUSDT","GMTUSDT","GMXUSDT","GNOUSDT","GRTUSDT","GTUSDT","GUSDUSDT","HBARUSDT","HIVEUSDT","HNTUSDT","HOTUSDT","HTUSDT","ICPUSDT","ICXUSDT","ILVUSDT","IMXUSDT","INJUSDT","IOSTUSDT","IOTXUSDT","JASMYUSDT","JSTUSDT","KAVAUSDT","KCSUSDT","KDAUSDT","KLAYUSDT","KNCUSDT","KSMUSDT","LDOUSDT","LEOUSDT","LINKUSDT","LPTUSDT","LRCUSDT","LSKUSDT","LTCUSDT","LUNAUSDT","LUNCUSDT","MAGICUSDT","MANAUSDT","MASKUSDT","MATICUSDT","MDXUSDT","MEDUSDT","METISUSDT","MINAUSDT","MIOTAUSDT","MKRUSDT","MXUSDT","MXCUSDT","NEARUSDT","NEOUSDT","NEXOUSDT","NFTUSDT","OCEANUSDT","OKBUSDT","OMGUSDT","ONEUSDT","ONGUSDT","ONTUSDT","OPUSDT","OSMOUSDT","PAXGUSDT","PEOPLEUSDT","PLAUSDT","POLYUSDT","PUNDIXUSDT","PYRUSDT","QNTUSDT","QTUMUSDT","RBNUSDT","REQUSDT","RLCUSDT","RNDRUSDT","ROSEUSDT","RSRUSDT","RUNEUSDT","RVNUSDT","SANDUSDT","SCUSDT","SCRTUSDT","SFPUSDT","SHIBUSDT","SKLUSDT","SLPUSDT","SNTUSDT","SNXUSDT","SOLUSDT","SSVUSDT","STORJUSDT","STXUSDT","SUSHIUSDT","SXPUSDT","SYSUSDT","TUSDT","TFUELUSDT","THETAUSDT","TONUSDT","TRIBEUSDT","TRXUSDT","TUSDUSDT","TWTUSDT","UMAUSDT","UNIUSDT","USDCUSDT","USDDUSDT","USDNUSDT","USDPUSDT","USDTUSDT","USTCUSDT","VETUSDT","VGXUSDT","WAVESUSDT","WAXPUSDT","WBTCUSDT","WINUSDT","WOOUSDT","XCHUSDT","XCNUSDT","XDCUSDT","XECUSDT","XEMUSDT","XLMUSDT","XMRUSDT","XNOUSDT","XRPUSDT","XTZUSDT","XYMUSDT","YFIUSDT","ZECUSDT","ZENUSDT","ZILUSDT","ZRXUSDT"]
#coins = ["ETHUSDT"]


#-----------Global variables------------#
sl_p = 0
tp_p = 0



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
        self.ema_50 = self.I(ta.trend.ema_indicator, pd.Series(close), window=50)
        self.ema_20  = self.I(ta.trend.ema_indicator, pd.Series(close), window=20)

    def next(self):
        price = self.data.Close

        global sl_p
        global tp_p

        sl = price * sl_p
        tp = price * tp_p

        if crossover(self.macd, self.macd_signal) and price > self.ema_20 and self.ema_20 > self.ema_50:
            self.buy(sl = sl, tp = tp)
        elif crossover(self.macd, self.macd_signal) and price < self.ema_20 and self.ema_20 < self.ema_50:
            self.sell(sl = tp, tp = sl)



#--Worker running different strategies--#
def worker_f(directory, loss, logging):
    ## Variable initialization
    results = {}
    sl_p = 1 - loss
    tp_p = 1 + 3 * loss

    for coin in coins:
        try:
            df = getData(coin, '2022-01-01')
            bt = Backtest(df, DataTrader, cash = 100000, commission = 0.0015)
            output = bt.run()
            results[coin] = output['Return [%]']
        except BinanceAPIException as e:
            if logging:
                cprint('Coin ' + coin + ' is not available', 'blue')
            continue
        except:
            if logging:
                cprint('An error occured for ' + coin, 'red')
            continue

    #cprint("\n\nsl = " + str(sl_p), "red")
    #cprint("tp = " + str(tp_p), "red")
    #colorful = highlight(
    #    formatted_json,
    #    lexer=JsonLexer(),
    #    formatter=Terminal256Formatter(),
    #)    
    #print(colorful)
    #cprint('\nAverage value : ' + str(res),'red')

    ## Average calculation
    average = 0
    for average in results.values():
        average += val
    average = average / len(results)

    ## Final json formatting
    final = {"average": average, "sl": sl_p, "tp": tp_p, "results": results}
    formatted_final = json.dumps(final, indent=4)
    print(formatted_final)

    ## Create output directories
    try:
        os.mkdir(directory + "/Strategy_statistics")
        cprint("Creation of " + directory + "/Strategy_statistics directory", 'blue')
    except FileExistsError:
        cprint("Directory " + directory + "/Strategy_statistics already exists", 'blue')
    except:
        raise

    ## Write into output directory
    output_file = directory + "/Strategy_statistics/sl_" + sl_p + "_tp_" + tp_p + ".json"
    print(output_file)
    with open(output_file, "w") as fp:
        fp.write(formatted_final)    
    


#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')

    ## Arguments
    parser.add_argument("-l", "--logging", action='store_true', dest="logging", help="enable logging in the console")
    required.add_argument("-d", "--directory", dest="directory", help="directory that will store results", required=True)
    return parser



#-------------Main Function-------------#
def main(args):
    ## Variables
    directory   = args.directory
    logging     = args.logging

    ## Multithread
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_f = {executor.submit(worker_f, directory, loss, logging): loss for loss in np.arange(0.01,0.1,0.01)}

        for future in concurrent.futures.as_completed(future_f):
            None



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
