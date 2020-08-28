package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import swing.common.SwingUtils;

import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

import static cic.cs.unb.ca.Sys.FILE_SEP;

public class worker implements Runnable {
    final private int minIndex; // first index, inclusive
    final private int maxIndex; // last index, exclusive
    final private File[] data;
    final private String outPath;
    final private long flowTimeout;
    final private long activityTimeout;

    public worker(int minIndex, int maxIndex, File[] data, String outpath, long flowtimeout, long activitytimeout) {
        this.minIndex = minIndex;
        this.maxIndex = maxIndex;
        this.data = data;
        this.outPath = outpath;
        this.flowTimeout = flowtimeout;
        this.activityTimeout =activitytimeout;
    }


    @Override
    public void run() {
        for(int i = minIndex; i < maxIndex; i++) {
            File file = data[i];
            if (file.isDirectory()) {
                return;
            }
            int cur = i + 1;
            System.out.println(String.format("==> %d / %d", cur, maxIndex));
            readPcapFile(file.getPath(), outPath, flowTimeout, activityTimeout);

        }

    }

    private static void readPcapFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if (inputFile == null || outPath == null) {
            return;
        }
        String fileName = FilenameUtils.getName(inputFile);

        if (!outPath.endsWith(FILE_SEP)) {
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath + fileName + FlowMgr.FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Save file can not be deleted");
            }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new Cmd.FlowListener(fileName, outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s", fileName));

        AtomicInteger nValid = new AtomicInteger(0);
        AtomicInteger nTotal = new AtomicInteger(0);
        AtomicInteger nDiscarded = new AtomicInteger(0);
        int threadcount = 5;
        Thread[] threads = new Thread[threadcount];

        for(int i = 0; i < threadcount; i++){

            threads[i] = new Thread(() -> {

                while (true) {
                    try{

                        BasicPacketInfo basicPacket = packetReader.nextPacket();
                        nTotal.addAndGet(1);
                        if (basicPacket != null) {
                            flowGen.addPacket(basicPacket);
                            nValid.addAndGet(1);
                        } else {
                            nDiscarded.addAndGet(1);
                        }

                    }catch(PcapClosedException e){
                        break;
                    }

                }


            });

            threads[i].start();

        }


        for(int j = 0; j < threadcount; j++){
            try{
                threads[j].join();
            }catch (InterruptedException e){
                e.printStackTrace();
            }
        }



        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

        long lines = SwingUtils.countLines(saveFileFullPath.getPath());

        System.out.println(String.format("%s is done. total %d flows ", fileName, lines));
        System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d", nTotal.get(), nValid.get(), nDiscarded.get()));

        //long end = System.currentTimeMillis();
        //logger.info(String.format("Done! in %d seconds",((end-start)/1000)));
        //logger.info(String.format("\t Total packets: %d",nTotal));
        //logger.info(String.format("\t Valid packets: %d",nValid));
        //logger.info(String.format("\t Ignored packets:%d %d ", nDiscarded,(nTotal-nValid)));
        //logger.info(String.format("PCAP duration %d seconds",((packetReader.getLastPacket()- packetReader.getFirstPacket())/1000)));
        //int singleTotal = flowGen.dumpLabeledFlowBasedFeatures(outPath, fileName+ FlowMgr.FLOW_SUFFIX, FlowFeature.getHeader());
        //logger.info(String.format("Number of Flows: %d",singleTotal));
        //logger.info("{} is done,Total {} flows",inputFile,singleTotal);
        //System.out.println(String.format("%s is done,Total %d flows", inputFile, singleTotal));
    }


}
