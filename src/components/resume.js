import React, { Component } from 'react';
import { Grid, Cell } from 'react-mdl';
import Education from './education';
import Experience from './experience';
import Psh from './CSS/psh.jpeg';


class Resume extends Component {
    render() {
        return (
            <div>
                <Grid>
                    <Cell col={4}>
                        <div style={{ textAlign: 'center' }}>
                            <img
                                src={Psh}
                                alt="myshoumei"
                                style={{ height: '400px',borderRadius:'30px' }}
                            />
                        </div>
                        <h2 style={{ paddingTop: '1' }}>朴 相炫 <h4>パク サンヒョン Park SangHyun</h4></h2>
                        <h4 style={{ color: 'black' }}>👨‍💻Programmer</h4>
                        <hr style={{ borderTop: '3px solid #174DBA', width: '80%' }} />
                        私の個人ホームページにご覧頂きありがとうございます。
                        <br/>
                            ITに魅力を感じ、専攻を変更してから、絶えず自己開発に全力で尽くしています。 <br/>  
                            色んなところで活躍できるエンジニアになりたいと思います。<br/> よろしくお願いします。
                       
                        <hr style={{ borderTop: '3px solid #174DBA', width: '50%' }} />
                        <h5>🏠Address</h5>
                        <p>韓国　ソウル特別市　ドボン区</p>
                        <h5>📲Phone</h5>
                        <p>010-2197-1370</p>
                        <h5>📩E-mail</h5>
                        <p>rainbluebird8@gmail.com</p>
                        <hr style={{ borderTop: '3px solid #174DBA', width: '50%' }} />
                    </Cell>



                    <Cell className="resume-right-col" col={8} >
                        <h2>Education</h2>
                        <Education
                            startYear="2017.3 "
                            endYear=" 2013.2"
                            schoolName="信韓大学校"
                            schoolDescription="国際観光経営学科"
                        />

                        <Education
                            startYear="2016.4 "
                            endYear=" 2016.10"
                            schoolName="鐘路 中央HTA"
                            schoolDescription="ウェブサーバーサイドプロセス"
                        />
                        <hr style={{ borderTop: '3px solid #D8EFE6' }}></hr>

                        <h2>Experience</h2>
                        <Experience
                       startYear="2008.2 "
                       endYear="2010.1"
                       jobName="海兵隊 ヨンピョン部隊"
                       jobDescription="兵長 除隊"
                   />
                     <Experience
                       startYear="2013.3 "
                       endYear=" 2015.3"
                       jobName="ソウル ホテル"
                       jobDescription="ハウスキーピング 勤務"
                   />
                   <Experience
                       startYear="2015.4 "
                       endYear=" 2016.1"
                       jobName="日本"
                       jobDescription="日本 ワーキングホリデー"
                   />
                    <Experience
                       startYear="2017.11 "
                       endYear=" 2018.4"
                       jobName="日本 NTT DOCOMO"
                       jobDescription="DOCOMO 派遣勤務"
                   />
                    <Experience
                       startYear="2018.5 "
                       endYear=" 2019.5"
                       jobName="日本 DENSO"
                       jobDescription="DENSO 派遣勤務"
                   />
                      <Experience
                       startYear="2019.6 "
                       endYear=" 2019.11"
                       jobName="日本 TOYOTA"
                       jobDescription=" TOYOTA 派遣勤務"
                   />
                   <Experience
                       startYear="2019.12 "
                       endYear=" 2020.4"
                       jobName="日本 TOYOTA SYSTEMS"
                       jobDescription=" TOYOTA SYSTEMS 派遣勤務"
                   />
                    <Experience
                       startYear="2020.5 "
                       endYear=" 2020.10"
                       jobName="日本 OPENSESAME TEC"
                       jobDescription=" OPENSESAME TEC 勤務"
                   />
                    <Experience
                       startYear="2020.12 "
                       endYear=" 現在"
                       jobName="韓国 MEDIAGROUP人と森"
                       jobDescription=" MEDIA GROUP　人と森　勤務"
                   />

                   <hr style={{ borderTop: '3px solid #D8EFE6' }}></hr>


 </Cell>
                </Grid>
            </div>
        )
    }
}
export default Resume;
